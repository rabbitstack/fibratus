// +build windows

/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package term

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	setConsoleCursorInfo       = kernel32.NewProc("SetConsoleCursorInfo")
	getConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
	writeConsoleOutput         = kernel32.NewProc("WriteConsoleOutputW")

	fillConsoleOutputCharacter = kernel32.NewProc("FillConsoleOutputCharacterW")
	fillConsoleOutputAttribute = kernel32.NewProc("FillConsoleOutputAttribute")
)

type point struct {
	x int16
	y int16
}

func (p point) uintptr() uintptr { return uintptr(*(*int32)(unsafe.Pointer(&p))) }

type rect struct {
	left, top     int16
	right, bottom int16
}

//nolint:unused
func (r *rect) uintptr() uintptr { return uintptr(unsafe.Pointer(r)) }

type charInfo struct {
	char uint16
	attr uint16
}

type consoleScreenBufferInfo struct {
	size       point
	_          point
	attributes uint16
	_          rect
	_          point
}

type consoleCursorInfo struct {
	size    uint32
	visible bool
}

// getScreenBufferInfo retrieves information about the specified console screen buffer.
func getScreenBufferInfo(cons syscall.Handle) (*consoleScreenBufferInfo, error) {
	var bi consoleScreenBufferInfo
	errno, _, err := getConsoleScreenBufferInfo.Call(uintptr(cons), uintptr(unsafe.Pointer(&bi)))
	if errno == 0 {
		return nil, err
	}
	return &bi, nil
}

// GetColumns gets the number of character columns.
func GetColumns() int {
	bufferInfo, err := getScreenBufferInfo(syscall.Handle(os.Stdout.Fd()))
	if err != nil {
		return 0
	}
	return int(bufferInfo.size.x)
}

// showCursor shows/hides the cursor.
func showCursor(cons syscall.Handle, visible bool) {
	var ci consoleCursorInfo
	ci.size = 100
	ci.visible = visible
	_, _, _ = setConsoleCursorInfo.Call(uintptr(cons), uintptr(unsafe.Pointer(&ci)))
}
