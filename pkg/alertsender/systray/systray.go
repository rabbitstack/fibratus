//go:build windows

/*
 * Copyright 2026 by Nedim Sabic Sabic
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package systray

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/sys"
	yconfig "github.com/rabbitstack/fibratus/pkg/yara/config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const (
	// pipeSDDL is the security descriptor of the systray pipe. LocalSystem and
	// the Administrators get full control. Interactive users (anyone logged on
	// locally or over RDP) are only granted FILE_GENERIC_READ, which is enough to
	// connect and receive notifications. Nobody else, not even the interactive
	// users, can write to the pipe or create additional instances of it, so the
	// server instance can't be impersonated by another process.
	pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120089;;;IU)"

	// writeTimeout bounds the time spent writing to a single client.
	// A hung client is dropped instead of stalling alert delivery.
	writeTimeout = 2 * time.Second

	// helperExitTimeout is the time given to the child helper process
	// to exit on its own before it is terminated, in milliseconds.
	helperExitTimeout = 2000

	// defaultTitle is the title of the balloon for all
	// but the YARA threat alerts.
	defaultTitle = "Malicious Activity Detected"
)

// launchHelper starts the `fibratus systray` helper process. It is a variable so
// the tests can swap it out. Without that, the test binary would launch itself.
var launchHelper = startHelper

// systray delivers alerts to the taskbar status area as balloon notifications.
//
// The Fibratus service runs in session 0, which is isolated from the interactive
// desktop, so it can't talk to the status area on its own. The service hosts a named
// pipe and the `fibratus systray` helpers that start at logon connect to it as clients.
// The service never starts, impersonates, or otherwise reaches into a user session.
// It publishes notifications, and any helper that connected receives them.
type systray struct {
	config Config
	l      net.Listener

	// sendMu serializes writes so frames from concurrent
	// alerts never interleave on a client connection
	sendMu sync.Mutex

	mu      sync.Mutex
	clients map[net.Conn]struct{}
	closed  bool

	// noClientsWarned rate limits the warning emitted when
	// alerts are dropped because there is nobody to show them to
	noClientsWarned atomic.Bool

	wg sync.WaitGroup

	// child is the helper process started when Fibratus runs in the foreground
	child windows.Handle
}

func init() {
	alertsender.Register(alertsender.Systray, makeSender)
}

// makeSender constructs a new instance of the systray alert sender.
func makeSender(config alertsender.Config) (alertsender.Sender, error) {
	c, ok := config.Sender.(Config)
	if !ok {
		return nil, alertsender.ErrInvalidConfig(alertsender.Systray)
	}

	if !c.Enabled {
		return &systray{}, nil
	}

	l, err := winio.ListenPipe(systrayPipe, &winio.PipeConfig{SecurityDescriptor: pipeSDDL})
	if err != nil {
		// The pipe is created as the first instance, so this fails if the name is
		// already taken. That's the case if another Fibratus process serves it or
		// something is squatting on the name
		log.Errorf("unable to listen on %s systray pipe: %v", systrayPipe, err)
		return &systray{}, nil
	}

	s := &systray{config: c, l: l, clients: make(map[net.Conn]struct{})}

	s.wg.Add(1)
	go s.accept()

	if sys.IsWindowsService() {
		log.Infof("systray alert sender listening on %s. Notifications are shown by the "+
			"`fibratus systray` helpers running in the interactive user sessions", systrayPipe)
		return s, nil
	}

	// If Fibratus is running in the foreground, it shares the session with the user, so it's
	// safe to start the helper ourselves. If another helper is already running in the session,
	// the new process exits right away and the existing one serves the notifications.
	proc, err := launchHelper()
	if err != nil {
		log.Warnf("unable to start the systray helper process: %v", err)
		return s, nil
	}
	s.child = proc

	return s, nil
}

func (s *systray) Send(alert alertsender.Alert) error {
	return s.broadcast(Balloon, notification(alert))
}

func (*systray) Type() alertsender.Type { return alertsender.Systray }
func (*systray) SupportsMarkdown() bool { return false }

func (s *systray) Shutdown() error {
	if s.l == nil {
		return nil
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	clients := make([]net.Conn, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.clients = make(map[net.Conn]struct{})
	s.mu.Unlock()

	err := s.l.Close()
	for _, c := range clients {
		_ = c.Close()
	}
	s.wg.Wait()

	if s.child != 0 {
		// closing the pipe makes the helper we started exit by itself
		// but if it stays around, terminate it so it can't outlive us
		_, _ = windows.WaitForSingleObject(s.child, helperExitTimeout)
		if sys.IsProcessRunning(s.child) {
			_ = windows.TerminateProcess(s.child, 1)
		}
		_ = windows.CloseHandle(s.child)
		s.child = 0
	}

	return err
}

// accept registers the clients as they connect.
func (s *systray) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.l.Accept()
		if err != nil {
			if errors.Is(err, winio.ErrPipeListenerClosed) {
				return
			}
			// don't spin if the error persists
			time.Sleep(time.Millisecond * 100)
			continue
		}
		s.register(conn)
	}
}

// register hands the settings to a new client and adds it to the delivery set.
func (s *systray) register(conn net.Conn) {
	conf, err := encodeMsg(Conf, Settings{Sound: s.config.Sound, QuietMode: s.config.QuietMode})
	if err != nil {
		log.Warnf("unable to encode systray settings: %v", err)
		_ = conn.Close()
		return
	}

	// settings have to be the first thing the client sees
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	if err := write(conn, conf); err != nil {
		log.Warnf("unable to send settings to systray client: %v", err)
		_ = conn.Close()
		return
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = conn.Close()
		return
	}
	s.clients[conn] = struct{}{}
	n := len(s.clients)
	s.mu.Unlock()

	s.noClientsWarned.Store(false)
	log.Infof("systray client connected. %d active client(s)", n)

	// Clients never send anything. Reading from the connection lets us notice
	// that the client went away without having to wait for the next alert, and
	// discards whatever a misbehaving client might write.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		_, _ = io.Copy(io.Discard, conn)
		s.drop(conn)
	}()
}

// drop removes the client and closes its connection.
func (s *systray) drop(conn net.Conn) {
	s.mu.Lock()
	_, ok := s.clients[conn]
	delete(s.clients, conn)
	n := len(s.clients)
	s.mu.Unlock()

	_ = conn.Close()
	if ok {
		log.Infof("systray client disconnected. %d active client(s)", n)
	}
}

// broadcast delivers the message to all connected clients. Not having any client
// is a normal condition (e.g. nobody is logged in), so it is not reported as an
// error to the alert emitters. It is logged once, though, so a misconfigured
// deployment where the helper never starts doesn't go unnoticed.
func (s *systray) broadcast(typ MsgType, data any) error {
	if s.l == nil {
		return nil
	}

	b, err := encodeMsg(typ, data)
	if err != nil {
		return err
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	s.mu.Lock()
	clients := make([]net.Conn, 0, len(s.clients))
	for c := range s.clients {
		clients = append(clients, c)
	}
	s.mu.Unlock()

	if len(clients) == 0 {
		if s.noClientsWarned.CompareAndSwap(false, true) {
			log.Warn("no systray client is connected, so notifications are dropped. " +
				"Notifications are shown by the `fibratus systray` helpers that start when a user logs on")
		}
		return nil
	}

	var delivered int
	var errs []error
	for _, c := range clients {
		if err := write(c, b); err != nil {
			errs = append(errs, err)
			s.drop(c)
			continue
		}
		delivered++
	}
	if delivered == 0 {
		return fmt.Errorf("unable to deliver the systray notification: %w", errors.Join(errs...))
	}

	return nil
}

func write(conn net.Conn, b []byte) error {
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	_, err := conn.Write(b)
	return err
}

// notification builds the balloon contents. The YARA threat alerts carry
// meaningful titles and texts, whereas for the rest of alerts the title
// is promoted to the balloon text under a generic caption.
func notification(alert alertsender.Alert) Notification {
	var n Notification
	switch alert.Title {
	case yconfig.MemoryThreatAlertTitle, yconfig.FileThreatAlertTitle:
		n.Title, n.Text = alert.Title, alert.Text
	default:
		n.Title, n.Text = defaultTitle, alert.Title
	}
	n.Title = truncate(n.Title, maxTitleLen)
	n.Text = truncate(n.Text, maxTextLen)
	return n
}

// startHelper starts `fibratus systray` as a child of the current process. It runs the
// very same executable as the caller instead of looking up a sibling binary and the
// application name is passed explicitly, so a path with spaces can't be misinterpreted
// by the command line parser. The helper exits when the pipe closes.
func startHelper() (windows.Handle, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, err
	}
	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	cmdline, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{exe, "systray", "--exit-on-disconnect"}))
	if err != nil {
		return 0, err
	}

	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation

	log.Infof("starting systray helper process %q", exe)

	err = windows.CreateProcess(app, cmdline, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, &si, &pi)
	if err != nil {
		return 0, err
	}
	_ = windows.CloseHandle(pi.Thread)

	return pi.Process, nil
}
