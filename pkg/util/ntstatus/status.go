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

package ntstatus

import (
	"github.com/rabbitstack/fibratus/pkg/zsyscall"
	"golang.org/x/sys/windows"
	"sync"
	"unicode/utf16"
)

var statusCache = map[uint32]string{}
var mux sync.Mutex

// isSuccess determines if the status code is in success or information value ranges.
// https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values
func isSuccess(status uint32) bool {
	return status <= 0x3FFFFFFF || (status >= 0x40000000 && status <= 0x7FFFFFFF)
}

// FormatMessage resolved the NT status code to an error message. The cache of resolved
// messages is kept to speed up status code translation and alleviate the pressure on
// API call invocations.
func FormatMessage(status uint32) string {
	if isSuccess(status) {
		return "Success"
	}
	mux.Lock()
	defer mux.Unlock()
	if s, ok := statusCache[status]; ok {
		return s
	}
	var flags uint32 = windows.FORMAT_MESSAGE_FROM_SYSTEM
	b := make([]uint16, 300)
	msgID := zsyscall.RtlNtStatusToDosError(status)
	n, err := windows.FormatMessage(flags, 0, msgID, 0, b, nil)
	if err != nil {
		return "Unknown"
	}
	// trim terminating \r and \n
	for ; n > 0 && (b[n-1] == '\n' || b[n-1] == '\r'); n-- {
	}
	statusCache[status] = string(utf16.Decode(b[:n-1]))
	return statusCache[status]
}
