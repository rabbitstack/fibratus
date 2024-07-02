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

import "golang.org/x/sys/windows"

// Hwnd defines the window handle type
type Hwnd uintptr

// InvalidHwnd designates an invalid window handle
const InvalidHwnd = 0

// WmClose is the message sent to the window procedure
// when the application is about to shut down
const WmClose = 0x10

// Hicon defines the icon handle type
type Hicon uintptr

// Destroy destroys the window.
func (w Hwnd) Destroy() {
	DestroyWindow(w)
}

// IsValid indicates if the window handle is valid.
func (w Hwnd) IsValid() bool { return w != 0 }

// Destroy destroys an icon and frees any memory the icon occupied.
func (i Hicon) Destroy() {
	DestroyIcon(i)
}

// Atom is an opaque data type. It can be
// used to represent the window class being
// registered with RegisterClass API function
type Atom uint16

// WndClassEx contains window class information.
type WndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

const (
	// WindowStyleOverlapped window is an overlapped window.
	// An overlapped window has a title bar and a border.
	WindowStyleOverlapped = 0x00000000

	// CwUseDefault  instructs the system selects the default
	// position for the window's upper-left corner.
	CwUseDefault = ^0x7fffffff

	// LoadResourceDefaultSize uses the width or height specified
	// by the system metric values for cursors or icons.
	LoadResourceDefaultSize = 0x00000040
	// LoadResourceFromFile loads the standalone image from the file
	// specified by name (icon, cursor, or bitmap file).
	LoadResourceFromFile = 0x00000010
)
