//go:build windows

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

	"golang.org/x/sys/windows"
)

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
