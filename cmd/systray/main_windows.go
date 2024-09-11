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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Microsoft/go-winio"
	"github.com/mitchellh/mapstructure"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/alertsender/systray"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/log"
	"github.com/rabbitstack/fibratus/pkg/util/signals"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"unsafe"
)

const systrayPipe = `\\.\pipe\fibratus-systray`

type MsgType uint8

const (
	Config MsgType = iota
	Balloon
)

var (
	className = windows.StringToUTF16Ptr("fibratus")
)

// Msg represents the data exchanged between systray client/server.
type Msg struct {
	Type MsgType `json:"type"`
	Data any     `json:"data"`
}

func (m Msg) decode(output any) error {
	var decoderConfig = &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           output,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return err
	}
	return decoder.Decode(m.Data)
}

type Systray struct {
	systrayIcon *sys.SystrayIcon
	window      sys.Hwnd
	config      systray.Config
	quit        chan struct{}
}

func newSystray() (*Systray, error) {
	var mod windows.Handle
	err := windows.GetModuleHandleEx(0, nil, &mod)
	if err != nil {
		return nil, err
	}

	tray := &Systray{quit: signals.Install()}

	hwnd, err := tray.createNotifyIconWindow(mod)
	if err != nil {
		return nil, err
	}
	tray.window = hwnd
	tray.systrayIcon, err = sys.NewSystrayIcon(hwnd)
	if err != nil {
		return nil, err
	}
	ico, err := tray.loadIconFromResource(mod)
	if err != nil {
		return nil, err
	}
	if err := tray.systrayIcon.SetIcon(sys.Hicon(ico)); err != nil {
		return nil, fmt.Errorf("unable to set systray icon: %v", err)
	}
	if err := tray.systrayIcon.SetTooltip("Fibratus"); err != nil {
		return nil, fmt.Errorf("unable to set systray icon tooltip: %v", err)
	}

	return tray, nil
}

func (s *Systray) shutdown() error {
	if s.window.IsValid() {
		s.window.Destroy()
	}
	return s.systrayIcon.Delete()
}

func (s *Systray) createNotifyIconWindow(mod windows.Handle) (sys.Hwnd, error) {
	// register notification icon window class
	var wc sys.WndClassEx
	wc.Size = uint32(unsafe.Sizeof(wc))
	wc.Instance = mod
	wc.WndProc = windows.NewCallback(s.wndProc)
	wc.ClassName = className
	err := sys.RegisterClass(&wc)
	if err != nil {
		return sys.InvalidHwnd, err
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
		return sys.InvalidHwnd, err
	}
	return hwnd, nil
}

func (s *Systray) loadIconFromResource(mod windows.Handle) (windows.Handle, error) {
	// find the icon in the same directory where the binary is loaded
	exe, err := os.Executable()
	if err != nil {
		return windows.InvalidHandle, err
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
			return windows.InvalidHandle, fmt.Errorf("unable to load systray icon resource: %v", err)
		}
		ico = windows.Handle(icon.Icon)
	}
	return ico, nil
}

func (s *Systray) handlePipeClient(conn net.Conn) {
	buf := make([]byte, 1024)
	defer conn.Close()
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if err != io.EOF {
				logrus.Errorf("pipe read: %v", err)
			}
			break
		}
		var m Msg
		err = json.Unmarshal(buf[:n], &m)
		if err != nil {
			logrus.Error(err)
			break
		}
		err = s.handleMessage(m)
		if err != nil {
			logrus.Error(err)
			break
		}
	}
}

func (s *Systray) handleMessage(m Msg) error {
	switch m.Type {
	case Config:
		var c systray.Config
		err := m.decode(&c)
		if err != nil {
			return err
		}
		s.config = c
	case Balloon:
		var alert alertsender.Alert
		err := m.decode(&alert)
		if err != nil {
			return err
		}
		text := alert.Text
		// the balloon notification fails
		// to show up if the text is empty
		if text == "" {
			text = " "
		}
		return s.systrayIcon.ShowBalloonNotification(alert.Title, text, s.config.Sound, s.config.QuietMode)
	}
	return nil
}

func main() {
	err := log.InitFromConfig(log.Config{Level: "info", LogStdout: true}, "fibratus-systray.log")
	if err != nil {
		fmt.Printf("%v", err)
		os.Exit(1)
	}
	logrus.Info("starting systray server...")
	usr, err := user.Current()
	if err != nil {
		logrus.Fatalf("failed to retrieve the current user: %v", err)
	}
	// Named pipe security and access rights.
	// Give generic read/write access to the
	// current user SID
	descriptor := "D:P(A;;GA;;;" + usr.Uid + ")"
	// spin up named-pipe server
	l, err := winio.ListenPipe(systrayPipe, &winio.PipeConfig{SecurityDescriptor: descriptor})
	if err != nil {
		logrus.Fatalf("unable to listen on named pipe: %s: %v", systrayPipe, err)
	}

	// detach console
	sys.FreeConsole()

	tray, err := newSystray()
	if err != nil {
		logrus.Fatalf("unable to create systray: %v", err)
	}

	go func() {
		<-tray.quit
		l.Close()
		err := tray.shutdown()
		if err != nil {
			logrus.Warnf("fail to shutdown: %v", err)
		}
	}()

	// server loop
	for {
		conn, err := l.Accept()
		if err != nil {
			if errors.Is(err, winio.ErrPipeListenerClosed) {
				break
			}
			continue
		}
		go tray.handlePipeClient(conn)
	}
}

func (s *Systray) wndProc(hwnd uintptr, msg uint32, wparam, lparam uintptr) uintptr {
	if msg == sys.WmClose {
		s.quit <- struct{}{}
	}
	return sys.DefWindowProc(hwnd, msg, wparam, lparam)
}
