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
	"errors"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

var (
	// ErrSystrayIconRegisterClass is raised when the systray window class fails o register
	ErrSystrayIconRegisterClass = errors.New("unable to register systray icon window class")
	// ErrSystrayIconWindow is raised when the systray icon window can't be created
	ErrSystrayIconWindow = errors.New("unable to create systray icon window")

	className = windows.StringToUTF16Ptr("fibratus")
)

// systray interops with the status area
// to show balloon notifications with the
// desired title and text. Both, regular
// and balloon icons are also rendered when
// displaying the notification message.
type systray struct {
	wnd         sys.Hwnd // systray icon window handle
	systrayIcon *sys.SystrayIcon
	config      Config
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

	var mod windows.Handle
	err := windows.GetModuleHandleEx(0, nil, &mod)
	if err != nil {
		return nil, err
	}
	// register notification icon window class
	var wc sys.WndClassEx
	wc.Size = uint32(unsafe.Sizeof(wc))
	wc.Instance = mod
	wc.WndProc = windows.NewCallback(wndProc)
	wc.ClassName = className
	err = sys.RegisterClass(&wc)
	if err != nil {
		return nil, errors.Join(ErrSystrayIconRegisterClass, err)
	}
	// create the notification icon window
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
		mod,
		0,
	)
	if err != nil {
		return nil, errors.Join(ErrSystrayIconWindow, err)
	}

	systrayIcon, err := sys.NewSystrayIcon(hwnd)
	if err != nil {
		return nil, err
	}
	// find the icon in the same directory where the binary is loaded
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	ico, err := sys.LoadImage(
		mod,
		windows.StringToUTF16Ptr(filepath.Join(filepath.Dir(exe), "fibratus.ico")),
		1, // load icon
		0,
		0,
		sys.LoadResourceDefaultSize|sys.LoadResourceFromFile,
	)
	if err != nil {
		// load stock informational system icon
		var icon sys.ShStockIcon
		icon.Size = uint32(unsafe.Sizeof(icon))
		err := sys.SHGetStockIconInfo(79, 0x000000100, &icon)
		if err != nil {
			return nil, fmt.Errorf("unable to load systray icon resource: %v", err)
		}
		ico = windows.Handle(icon.Icon)
	}

	// set systray icon and tooltip
	if err := systrayIcon.SetIcon(sys.Hicon(ico)); err != nil {
		return nil, fmt.Errorf("unable to set systray icon: %v", err)
	}
	if err := systrayIcon.SetTooltip("Fibratus"); err != nil {
		return nil, fmt.Errorf("unable to set systray icon tooltip: %v", err)
	}
	s := &systray{
		wnd:         hwnd,
		systrayIcon: systrayIcon,
		config:      c,
	}
	return s, nil
}

func (s systray) Send(alert alertsender.Alert) error {
	if s.systrayIcon == nil {
		return nil
	}
	text := alert.Text
	// the balloon notification fails to
	// popup when the text is empty
	if text == "" {
		text = " "
	}
	return s.systrayIcon.ShowBalloonNotification(alert.Title, text, s.config.Sound, s.config.QuietMode)
}

func (s systray) Type() alertsender.Type { return alertsender.Systray }
func (s systray) SupportsMarkdown() bool { return false }

func (s systray) Shutdown() error {
	if s.wnd.IsValid() {
		s.wnd.Destroy()
	}
	if s.systrayIcon != nil {
		return s.systrayIcon.Delete()
	}
	return nil
}

func wndProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	return sys.DefWindowProc(hwnd, msg, wparam, lparam)
}
