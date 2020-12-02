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
	"fmt"
	"io"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	createConsoleScreenBuffer    = kernel32.NewProc("CreateConsoleScreenBuffer")
	setConsoleActiveScreenBuffer = kernel32.NewProc("SetConsoleActiveScreenBuffer")
)

const consoleTextModeBuffer = 0x1

// FrameBuffer is a special type of the I/O writer that outputs the character stream to the
// active console screen buffer.
type FrameBuffer struct {
	handle syscall.Handle
}

// NewFrameBuffer builds a fresh frame buffer.
func NewFrameBuffer() (io.Writer, error) {
	handle, _, err := createConsoleScreenBuffer.Call(
		uintptr(syscall.GENERIC_READ|syscall.GENERIC_WRITE),
		uintptr(0),
		uintptr(0),
		uintptr(consoleTextModeBuffer),
		uintptr(0),
		uintptr(0),
	)
	if handle == 0 {
		return nil, fmt.Errorf("unable to create screen buffer: %v", err)
	}
	fb := &FrameBuffer{
		handle: syscall.Handle(handle),
	}
	errno, _, err := setConsoleActiveScreenBuffer.Call(uintptr(handle))
	if errno == 0 {
		return nil, fmt.Errorf("couldn't activate console screen buffer")
	}
	showCursor(fb.handle, false)
	return fb, nil
}

// Write draws the character buffer to the screen frame buffer.
func (fb FrameBuffer) Write(p []byte) (int, error) {
	bufferInfo, err := getScreenBufferInfo(fb.handle)
	if err != nil {
		return 0, err
	}
	if len(p) == 1 {
		return 0, nil
	}

	rows := int(bufferInfo.size.y)
	cols := int(bufferInfo.size.x)

	chars := make([]charInfo, cols*rows)

	var x int
	var y int
	var newLine bool

	for _, char := range string(p) {
		c := char
		if c == '\n' || c == '\r' {
			newLine = true
		}
		r, c := utf16.EncodeRune(c)
		if r == 0xFFFD {
			c = char
		}
		y++
		// if the last column has been reached and a new line was encountered at
		// that position then we'll stop the iteration and reset the column number
		if y == cols {
			y = 0
			if newLine {
				newLine = false
				continue
			}
		}
		if newLine {
			newLine = false
			space := y
			// keep filling the rectangle with spaces until we reach the last column. Then
			// we'll reset the column and stop the current iteration
			for space <= cols {
				if space-1 > len(chars)-1 {
					continue
				}
				chars[space-1].char = uint16(' ')
				space++
				x++
			}
			y = 0
			continue
		}

		if x > len(chars)-1 {
			continue
		}

		chars[x].char = uint16(c)
		chars[x].attr = bufferInfo.attributes
		x++
	}

	// clear the current frame buffer screen
	fb.cls(bufferInfo)
	// the following block of code does the heavy lifting of writing the
	// character buffer to the screen frame buffer that we previously created
	cord := point{}
	size := point{x: int16(cols), y: int16(rows)}
	rect := rect{left: 0, top: 0, right: int16(cols) - 1, bottom: int16(rows) - 1}
	_, _, _ = writeConsoleOutput.Call(
		uintptr(fb.handle),
		uintptr(unsafe.Pointer(&chars[0])),
		size.uintptr(),
		cord.uintptr(),
		uintptr(unsafe.Pointer(&rect)),
	)

	return 0, nil
}

// Close closes this frame buffer.
func (fb *FrameBuffer) Close() error {
	return syscall.Close(fb.handle)
}

// cls clears the frame buffer content.
func (fb *FrameBuffer) cls(bufferInfo *consoleScreenBufferInfo) {
	var w uint16
	var cursor point
	rows := bufferInfo.size.x
	cols := bufferInfo.size.y

	_, _, _ = fillConsoleOutputCharacter.Call(
		uintptr(fb.handle),
		uintptr(' '),
		uintptr(rows*cols),
		*(*uintptr)(unsafe.Pointer(&cursor)),
		uintptr(unsafe.Pointer(&w)),
	)

	_, _, _ = fillConsoleOutputAttribute.Call(
		uintptr(fb.handle),
		uintptr(bufferInfo.attributes),
		uintptr(rows*cols),
		*(*uintptr)(unsafe.Pointer(&cursor)),
		uintptr(unsafe.Pointer(&w)),
	)
}
