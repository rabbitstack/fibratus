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

package sys

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

const (
	NotifyIconGUIDFlag    = 0x00000020
	NotifyIconMessageFlag = 0x00000001
	NotifyIconInfoFlag    = 0x00000010
	NotifyIconIconFlag    = 0x00000002
	NotifyIconTipFlag     = 0x00000004

	// NotifyIconUserFlag specifies the icon identified in
	// the NotifyIconData structure is used as the notification
	// balloon's title icon.
	NotifyIconUserFlag = 0x00000004
	// NotifyIconNosoundFlag indicates not to play the associated
	// sound when the balloon notification is shown.
	NotifyIconNosoundFlag = 0x00000010
	// NotifyIconLargeIconFlag determines the large version of
	// the icon should be used as the notification icon
	NotifyIconLargeIconFlag = 0x00000020
	// NotifyIconRespectQuietTimeFlag instructs not to display
	// the balloon notification if the current user is in "quiet time".
	// During this time, most notifications should not be sent or shown.
	// This lets a user become accustomed to a new computer system without
	// those distractions. Quiet time also occurs for each user after an
	// operating system upgrade or clean installation.
	NotifyIconRespectQuietTimeFlag = 0x00000080
)

// SystrayIconGUID identifies the systray icon
var SystrayIconGUID = windows.GUID{Data1: 0x52cf1171, Data2: 0xfe06, Data3: 0xb859, Data4: [8]byte{0x9d, 0xda, 0x36, 0xc0, 0x4f, 0xd7, 0xba, 0xb9}}

// NotifyIconMessage defines message types that
// can be sent to the taskbar status area.
type NotifyIconMessage uint32

const (
	// ShellAddIcon adds an icon to the status area.
	ShellAddIcon NotifyIconMessage = 0x00000000
	// ShellModifyIcon modifies an icon in the status area.
	ShellModifyIcon NotifyIconMessage = 0x00000001
	// ShellDeleteIcon deletes an icon from the status area.
	ShellDeleteIcon NotifyIconMessage = 0x00000002
)

// NotifyIconData contains information that the system
// needs to display notifications in the notification area.
type NotifyIconData struct {
	Size            uint32
	HWnd            Hwnd
	UID             uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            Hicon
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUIDItem        windows.GUID
	BalloonIcon     Hicon
}

// SystrayIcon provides the mechanism for
// interacting with the systray icon.
type SystrayIcon struct {
	// wnd is the handle of the window
	// that receives notifications
	// associated with an icon in the
	// notification area
	wnd Hwnd
}

// NewSystrayIcon creates a new systray icon instance.
func NewSystrayIcon(wnd Hwnd) (*SystrayIcon, error) {
	var data NotifyIconData
	data.Size = uint32(unsafe.Sizeof(data))
	data.Flags = NotifyIconGUIDFlag | NotifyIconMessageFlag
	data.GUIDItem = SystrayIconGUID
	data.HWnd = wnd

	err := ShellNotifyIcon(ShellAddIcon, &data)
	si := &SystrayIcon{wnd: wnd}
	if err != nil {
		return nil, err
	}
	return si, nil
}

// SetIcon sets the tray icon.
func (s *SystrayIcon) SetIcon(icon Hicon) error {
	var data NotifyIconData
	data.Size = uint32(unsafe.Sizeof(data))
	data.Flags = NotifyIconGUIDFlag | NotifyIconIconFlag
	data.GUIDItem = SystrayIconGUID
	data.HWnd = s.wnd
	data.Icon = icon
	return ShellNotifyIcon(ShellModifyIcon, &data)
}

// SetTooltip sets the tray icon tooltip.
func (s *SystrayIcon) SetTooltip(tooltip string) error {
	var data NotifyIconData
	data.Size = uint32(unsafe.Sizeof(data))
	data.Flags = NotifyIconGUIDFlag | NotifyIconTipFlag
	data.GUIDItem = SystrayIconGUID
	data.HWnd = s.wnd
	tip := windows.StringToUTF16(tooltip)
	if len(tip) > 128 {
		tip = tip[:128]
	}
	copy(data.Tip[:], tip)
	return ShellNotifyIcon(ShellModifyIcon, &data)
}

// ShowBalloonNotification renders the balloon notification
// in the taskbar area. The icon is a customized notification
// icon provided by the application that should be used independently
// of the notification area icon. The balloon notification title
// appears in a larger font immediately above the text. The text is a
// string that specifies the text to display in a balloon notification.
// To disable playing the sound when the notification is shown, set the
// `sound` parameter to false. Also, to respect user quiet time and prevent
// displaying balloon notifications, set `quietMode` to true.
func (s *SystrayIcon) ShowBalloonNotification(title string, text string, sound, quietMode bool) error {
	var data NotifyIconData
	data.Size = uint32(unsafe.Sizeof(data))
	data.Flags = NotifyIconGUIDFlag | NotifyIconInfoFlag
	data.InfoFlags = NotifyIconUserFlag | NotifyIconLargeIconFlag
	if !sound {
		data.InfoFlags |= NotifyIconNosoundFlag
	}
	if quietMode {
		data.InfoFlags |= NotifyIconRespectQuietTimeFlag
	}
	data.GUIDItem = SystrayIconGUID
	data.HWnd = s.wnd

	s1, s2 := windows.StringToUTF16(title), windows.StringToUTF16(text)
	if len(s1) > 64 {
		s1 = s1[:64]
	}
	if len(s2) > 256 {
		s2 = s1[:256]
	}
	copy(data.Info[:], s2)
	copy(data.InfoTitle[:], s1)

	return ShellNotifyIcon(ShellModifyIcon, &data)
}

// Delete deletes systray icon and disposes all resources.
func (s *SystrayIcon) Delete() error {
	var data NotifyIconData
	data.Size = uint32(unsafe.Sizeof(data))
	data.Flags = NotifyIconGUIDFlag
	data.GUIDItem = SystrayIconGUID
	data.HWnd = s.wnd
	return ShellNotifyIcon(ShellDeleteIcon, &data)
}

// ShStockIcon receives information used to retrieve a stock shell icon.
type ShStockIcon struct {
	Size          uint32
	Icon          Hicon
	SysImageIndex int32
	IconIndex     int32
	Path          [260]uint16
}
