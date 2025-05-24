/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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
	"context"
	"encoding/json"
	"fmt"
	"github.com/Microsoft/go-winio"
	"github.com/cenkalti/backoff/v4"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/sys"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"math"
	"os"
	"path/filepath"
	"time"
)

const systrayPipe = `\\.\pipe\fibratus-systray`

// systray interops with the status area
// to show balloon notifications with the
// desired title and text. Both, regular
// and balloon icons are also rendered when
// displaying the notification message. The
// interactions with the status area are
// performed via IPC through named pipe.
// Systray process exposes the named pipe server
// and listen for incoming messages published
// by the systray sender.
type systray struct {
	config Config
	proc   windows.Handle // systray server process handle
}

// MsgType determines the type of the message sent
// to the systray named pipe server.
type MsgType uint8

const (
	Conf MsgType = iota
	Balloon
)

// Msg represents the data exchanged between systray client/server.
type Msg struct {
	Type MsgType `json:"type"`
	Data any     `json:"data"`
}

func (m Msg) encode() ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return b, err
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

	// spin up systray server process
	var si windows.StartupInfo
	var pi windows.ProcessInformation

	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmdline := filepath.Join(filepath.Dir(exe), "fibratus-systray.exe")
	argv, err := windows.UTF16PtrFromString(cmdline)
	if err != nil {
		return nil, err
	}

	log.Infof("starting systray server process %q", cmdline)

	if sys.IsWindowsService() {
		// if we're running inside Windows Service, the systray server
		// process must be created in the console session and with the
		// currently logged-in user access token
		var token windows.Token

		// enable TCB privilege to obtain the console session user token
		sys.SetTcbPrivilege()

		consoleSessionID := sys.WTSGetActiveConsoleSessionID()
		if consoleSessionID == math.MaxUint32 && sys.IsInSandbox() {
			// if we failed to obtain the console session ID and
			// are running inside Windows Sandbox, use session 1
			consoleSessionID = 1
		}

		if sys.WTSQueryUserToken(consoleSessionID, &token) {
			log.Infof("obtained user token for console session ID %d", consoleSessionID)
			err = windows.CreateProcessAsUser(
				token,
				nil,
				argv,
				nil,
				nil,
				false,
				windows.CREATE_NO_WINDOW,
				nil,
				nil,
				&si,
				&pi,
			)
		} else {
			err = fmt.Errorf("unable to obtain user token for console session ID %d", consoleSessionID)
		}

		// drop TCB privilege and close the token handle
		sys.RemoveTcbPrivilege()
		_ = windows.CloseHandle(windows.Handle(token))
	} else {
		err = windows.CreateProcess(
			nil,
			argv,
			nil,
			nil,
			false,
			windows.CREATE_NO_WINDOW,
			nil,
			nil,
			&si,
			&pi)
	}

	if err != nil {
		log.Warnf("unable to start systray server process: %v", err)
	}

	s := &systray{config: c}
	b := &backoff.ExponentialBackOff{
		// first backoff timeout will be somewhere in the 100 - 300 ms range given the default multiplier
		InitialInterval:     time.Millisecond * 200,
		RandomizationFactor: backoff.DefaultRandomizationFactor,
		Multiplier:          backoff.DefaultMultiplier,
		MaxInterval:         time.Second * 10,
		MaxElapsedTime:      time.Minute * 30,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}

	b.Reset()

	for {
		if !pipeExists() {
			backoffTime := b.NextBackOff()
			if backoffTime == backoff.Stop {
				return nil, fmt.Errorf("%s named pipe didn't appear after 30m", systrayPipe)
			}
			log.Warnf("systray pipe not ready. Trying to dial in %v...", backoffTime)
			time.Sleep(backoffTime)
			continue
		}
		break
	}

	log.Info("established connection to systray server")

	s.proc = pi.Process

	return s, s.send(&Msg{Type: Conf, Data: c})
}

func (s *systray) Send(alert alertsender.Alert) error {
	// remove all events to avoid decoding errors on systray server end
	alert.Events = make([]*event.Event, 0)
	return s.send(&Msg{Type: Balloon, Data: alert})
}

func (*systray) Type() alertsender.Type { return alertsender.Systray }
func (*systray) SupportsMarkdown() bool { return false }

func (s *systray) Shutdown() error {
	if s.proc != 0 && sys.IsProcessRunning(s.proc) {
		return windows.TerminateProcess(s.proc, 1)
	}
	return nil
}

func (s *systray) send(m *Msg) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	conn, err := winio.DialPipeContext(ctx, systrayPipe)
	if err != nil {
		return fmt.Errorf("unable to dial %s pipe: %v", systrayPipe, err)
	}
	defer conn.Close()

	b, err := m.encode()
	if err != nil {
		return err
	}
	if err = conn.SetDeadline(time.Now().Add(time.Second * 5)); err != nil {
		return err
	}
	if _, err = conn.Write(b); err != nil {
		return fmt.Errorf("unable to write systray pipe: %v", err)
	}

	return nil
}

func pipeExists() bool {
	_, err := os.Stat(systrayPipe)
	return err == nil
}
