/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package colorizer

import (
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
)

// escape sequences
const (
	reset = "\033[0m"
	bold  = "\033[1m"
	dim   = "\033[2m"
	fg    = "\033[38;5;"
)

// maps logical colour names to 256-colour foreground codes.
// All codes are tuned for dark terminal backgrounds.
const (
	Gray        uint8 = 244
	Blue        uint8 = 75
	Cyan        uint8 = 87
	Green       uint8 = 114
	Yellow      uint8 = 221
	Amber       uint8 = 215
	Magenta     uint8 = 177
	Red         uint8 = 203
	Coral       uint8 = 209
	Teal        uint8 = 80
	White       uint8 = 252
	Indigo      uint8 = 99
	IndigoDim   uint8 = 61
	Lavender    uint8 = 183
	LavenderDim uint8 = 140
)

// Span wraps text with a 256-colour foreground escape and a trailing reset.
func Span(code uint8, text string) string {
	var b strings.Builder
	b.Grow(len(text) + 40)
	b.WriteString(fg)
	b.WriteString(itoa(code))
	b.WriteByte('m')
	b.WriteString(text)
	b.WriteString(reset)
	return b.String()
}

// SpanBold wraps text with bold + 256-colour foreground.
func SpanBold(code uint8, text string) string {
	var b strings.Builder
	b.Grow(len(text) + 40)
	b.WriteString(fg)
	b.WriteString(itoa(code))
	b.WriteByte('m')
	b.WriteString(bold)
	b.WriteString(text)
	b.WriteString(reset)
	return b.String()
}

// SpanDim wraps text with dim intensity.
func SpanDim(text string) string {
	var b strings.Builder
	b.Grow(len(text) + 20)
	b.WriteString(dim)
	b.WriteString(text)
	b.WriteString(reset)
	return b.String()
}

// itoa converts a uint8 to its decimal string without importing strconv,
// keeping this package free of extra dependencies on the hot render path.
func itoa(n uint8) string {
	switch {
	case n < 10:
		return string([]byte{'0' + n})
	case n < 100:
		return string([]byte{'0' + n/10, '0' + n%10})
	default:
		return string([]byte{'0' + n/100, '0' + (n/10)%10, '0' + n%10})
	}
}

// IsAnsiEnabled reports whether the current process should emit ANSI codes.
// It honours NO_COLOR (https://no-color.org), checks for a non-TTY stdout,
// and, on Windows, enables VT-processing mode so that the same code path
// works from Windows 10+ without any conditional compilation.
func IsAnsiEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if strings.ToLower(os.Getenv("TERM")) == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		return enableWindowsVT()
	}
	return true
}

// enableWindowsVT activates ENABLE_VIRTUAL_TERMINAL_PROCESSING on the Windows
// console handle so that ANSI escape sequences are interpreted rather than
// printed verbatim. Returns false on pre-Windows 10 hosts where this flag
// is unavailable.
func enableWindowsVT() bool {
	handle := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	const vtFlag = 0x0004 // ENABLE_VIRTUAL_TERMINAL_PROCESSING
	if mode&vtFlag != 0 {
		return true
	}
	return windows.SetConsoleMode(handle, mode|vtFlag) == nil
}
