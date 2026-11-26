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
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/alertsender/systray"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/log"
	"github.com/rabbitstack/fibratus/pkg/util/signals"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
)

const (
	// instanceMutex guarantees a single helper per logon session.
	// The Local\ prefix scopes the mutex to the session namespace.
	instanceMutex = `Local\FibratusSystray`

	// wmNotify is posted to the window by the pipe reader
	// to hand over the pending notifications to the UI thread.
	wmNotify = 0x8000 + 1

	// resourceIconName is the name of the icon resource embedded in fibratus.exe.
	resourceIconName = "IDI_APP_ICON"

	// connectTimeout limits how long the helper waits for the pipe
	// to appear when it was asked to exit once the pipe goes away
	connectTimeout = 30 * time.Second

	maxBackoff = 10 * time.Second
)

var className = windows.StringToUTF16Ptr("FibratusSystrayWindow")

var exitOnDisconnect bool

// Command is the CLI command that shows the alert notifications in the taskbar status area.
var Command = &cobra.Command{
	Use:   "systray",
	Short: "Show the alert notifications in the taskbar status area of the current user session",
	Long: `Connects to the Fibratus service and displays the alerts emitted by the systray alert sender
as balloon notifications.

The Fibratus service runs in the isolated session 0 where there is no access to the interactive desktop.
For that reason, the service doesn't display the notifications itself, but publishes them over a named pipe
that is only writable by the service. This command is the receiving end of the pipe. It has to run in the
user session, which is what the Fibratus installer arranges by registering it to start at logon. Each logged-on
user runs its own instance.`,
	Example: `
	# Show the notifications in the current session
	fibratus systray
	`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         run,
	Hidden:       true,
}

func init() {
	Command.Flags().BoolVar(&exitOnDisconnect, "exit-on-disconnect", false,
		"Exit when the Fibratus process closes the pipe instead of waiting for it to come back. Used when Fibratus starts the helper itself")
}

func run(_ *cobra.Command, _ []string) error {
	if sys.IsWindowsService() {
		return errors.New("the systray command can't run as a Windows service. It must run in an interactive user session")
	}
	var sid uint32
	if err := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sid); err == nil && sid == 0 {
		return errors.New("the systray command can't run in session 0. It must run in an interactive user session")
	}

	// If the helper was started at logon, Windows allocates a console for the process
	// that would stay on the screen. Release the console if we are its only user.
	var pids [2]uint32
	hasConsole := sys.GetConsoleProcessList(&pids[0], uint32(len(pids))) > 1
	if !hasConsole {
		sys.FreeConsole()
	}

	// the installation directory is not writable by regular users, so logs go to the user profile
	logCfg := log.Config{Level: "info", LogStdout: hasConsole, Formatter: "text", MaxBackups: 3, MaxSize: 10}
	if dir := os.Getenv("LOCALAPPDATA"); dir != "" {
		logCfg.Path = filepath.Join(dir, "Fibratus", "Logs")
	}
	if err := log.InitFromConfig(logCfg, "fibratus-systray.log"); err != nil {
		// not being able to log is not a reason to give up showing the notifications
		fmt.Fprintf(os.Stderr, "unable to initialize logging: %v\n", err)
	}

	name, err := windows.UTF16PtrFromString(instanceMutex)
	if err != nil {
		return err
	}
	mutex, err := windows.CreateMutex(nil, false, name)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			logrus.Info("systray is already running in this session")
			_ = windows.CloseHandle(mutex)
			return nil
		}
		return fmt.Errorf("unable to create the systray instance mutex: %w", err)
	}
	defer windows.CloseHandle(mutex)

	// the window and its message loop must stay on the same OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	logrus.Info("starting systray...")

	tray, err := newTray()
	if err != nil {
		return fmt.Errorf("unable to create systray: %w", err)
	}

	quit := signals.Install()
	go func() {
		<-quit
		_ = sys.PostMessage(tray.window, sys.WmClose, 0, 0)
	}()

	go tray.receive()

	tray.loop()

	logrus.Info("systray stopped")
	return nil
}

// tray owns the notification icon and the hidden window that hosts it.
type tray struct {
	window sys.Hwnd
	mod    windows.Handle
	icon   *sys.SystrayIcon
	hicon  sys.Hicon

	// taskbarCreated is the id of the broadcast message sent after the shell
	// (re)starts. The icon has to be added again, because it is gone with the shell.
	taskbarCreated uint32

	mu       sync.Mutex
	settings systray.Settings
	pending  []systray.Notification
}

func newTray() (*tray, error) {
	var mod windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &mod); err != nil {
		return nil, err
	}

	t := &tray{mod: mod}

	msg, err := sys.RegisterWindowMessage(windows.StringToUTF16Ptr("TaskbarCreated"))
	if err != nil {
		logrus.Warnf("unable to register the TaskbarCreated message: %v", err)
	}
	t.taskbarCreated = msg

	// This has to be a regular top-level window, even though it is never shown. Message-only
	// windows can't receive the TaskbarCreated broadcast, and the installer can't close the
	// helper (WM_CLOSE) during an upgrade because it only enumerates top-level windows.
	if err := t.createWindow(); err != nil {
		return nil, err
	}
	if err := t.addIcon(); err != nil {
		t.window.Destroy()
		return nil, err
	}

	return t, nil
}

func (t *tray) createWindow() error {
	var wc sys.WndClassEx
	wc.Size = uint32(unsafe.Sizeof(wc))
	wc.Instance = t.mod
	wc.WndProc = windows.NewCallback(t.wndProc)
	wc.ClassName = className
	if err := sys.RegisterClass(&wc); err != nil {
		return err
	}
	hwnd, err := sys.CreateWindowEx(
		0,
		className,
		className,
		sys.WindowStyleOverlapped,
		sys.CwUseDefault,
		sys.CwUseDefault,
		100,
		100,
		0,
		0,
		t.mod,
		0,
	)
	if err != nil {
		return err
	}
	t.window = hwnd
	return nil
}

func (t *tray) addIcon() error {
	icon, err := sys.NewSystrayIcon(t.window)
	if err != nil {
		return err
	}
	if t.hicon == 0 {
		hicon, err := t.loadIcon()
		if err != nil {
			return err
		}
		t.hicon = hicon
	}
	if err := icon.SetIcon(t.hicon); err != nil {
		return fmt.Errorf("unable to set systray icon: %w", err)
	}
	if err := icon.SetTooltip("Fibratus"); err != nil {
		return fmt.Errorf("unable to set systray icon tooltip: %w", err)
	}
	t.icon = icon
	return nil
}

// loadIcon tries the icon embedded in the executable and then the
// icon file next to it before settling for a stock shell icon.
func (t *tray) loadIcon() (sys.Hicon, error) {
	const imageIcon = 1

	h, err := sys.LoadImage(t.mod, windows.StringToUTF16Ptr(resourceIconName), imageIcon, 0, 0, sys.LoadResourceDefaultSize)
	if err == nil {
		return sys.Hicon(h), nil
	}

	if exe, err := os.Executable(); err == nil {
		h, err := sys.LoadImage(
			t.mod,
			windows.StringToUTF16Ptr(filepath.Join(filepath.Dir(exe), "fibratus.ico")),
			imageIcon,
			0,
			0,
			sys.LoadResourceDefaultSize|sys.LoadResourceFromFile,
		)
		if err == nil {
			return sys.Hicon(h), nil
		}
	}

	// stock informational icon
	var stock sys.ShStockIcon
	stock.Size = uint32(unsafe.Sizeof(stock))
	if err := sys.SHGetStockIconInfo(79, 0x000000100, &stock); err != nil {
		return 0, fmt.Errorf("unable to load systray icon resource: %w", err)
	}
	return stock.Icon, nil
}

// loop pumps the window messages until the window is destroyed.
func (t *tray) loop() {
	var msg sys.WndMsg
	for {
		// GetMessage returns 0 on WM_QUIT and -1 on error
		if r := sys.GetMessage(&msg, 0, 0, 0); r == 0 || r == -1 {
			return
		}
		sys.TranslateMessage(&msg)
		sys.DispatchMessage(&msg)
	}
}

func (t *tray) wndProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	switch {
	case msg == wmNotify:
		t.flush()
		return 0
	case t.taskbarCreated != 0 && msg == t.taskbarCreated:
		logrus.Info("the shell was restarted. Adding the systray icon again")
		if err := t.addIcon(); err != nil {
			logrus.Errorf("unable to restore the systray icon: %v", err)
		}
		return 0
	case msg == sys.WmDestroy:
		if t.icon != nil {
			if err := t.icon.Delete(); err != nil {
				logrus.Warnf("unable to delete the systray icon: %v", err)
			}
		}
		sys.PostQuitMessage(0)
		return 0
	}
	return sys.DefWindowProc(hwnd, msg, wparam, lparam)
}

// flush shows the notifications enqueued by the pipe reader.
func (t *tray) flush() {
	t.mu.Lock()
	pending := t.pending
	t.pending = nil
	settings := t.settings
	t.mu.Unlock()

	for _, n := range pending {
		if err := t.icon.ShowBalloonNotification(n.Title, n.Text, settings.Sound, settings.QuietMode); err != nil {
			logrus.Errorf("unable to show the notification: %v", err)
		}
	}
}

// receive keeps the pipe connection alive and feeds the messages to the UI thread.
func (t *tray) receive() {
	var lastErr string
	var first = time.Now()
	backoff := 500 * time.Millisecond

	for {
		c, err := systray.Dial()
		if err != nil {
			// don't repeat the same error on every attempt
			if msg := err.Error(); msg != lastErr {
				logrus.Warnf("unable to connect to the Fibratus service: %v. Retrying...", err)
				lastErr = msg
			}
			if exitOnDisconnect && time.Since(first) > connectTimeout {
				logrus.Warn("giving up connecting to Fibratus")
				t.quit()
				return
			}
			time.Sleep(backoff)
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		logrus.Info("connected to the Fibratus service")
		lastErr = ""
		backoff = 500 * time.Millisecond

		err = t.consume(c)
		_ = c.Close()

		if exitOnDisconnect {
			logrus.Infof("the Fibratus service closed the pipe: %v", err)
			t.quit()
			return
		}
		logrus.Infof("connection to the Fibratus service lost: %v. Reconnecting...", err)
		first = time.Now()
	}
}

// consume reads messages until the connection ends.
func (t *tray) consume(c *systray.Client) error {
	for {
		m, err := c.Recv()
		if err != nil {
			return err
		}
		switch m.Type {
		case systray.Conf:
			var s systray.Settings
			if err := m.Decode(&s); err != nil {
				logrus.Errorf("unable to decode the systray settings: %v", err)
				continue
			}
			t.mu.Lock()
			t.settings = s
			t.mu.Unlock()
		case systray.Balloon:
			var n systray.Notification
			if err := m.Decode(&n); err != nil {
				logrus.Errorf("unable to decode the notification: %v", err)
				continue
			}
			t.mu.Lock()
			t.pending = append(t.pending, n)
			t.mu.Unlock()
			// the shell calls have to be made by the thread that owns the window
			if err := sys.PostMessage(t.window, wmNotify, 0, 0); err != nil {
				logrus.Errorf("unable to hand over the notification to the UI thread: %v", err)
			}
		default:
			logrus.Warnf("ignoring unknown systray message type %d", m.Type)
		}
	}
}

func (t *tray) quit() {
	_ = sys.PostMessage(t.window, sys.WmClose, 0, 0)
}
