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

package interceptors

import (
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"

	"github.com/rabbitstack/fibratus/pkg/syscall/sys"
	"golang.org/x/sys/windows"
)

// statusCache keeps the mappings of formatted NT status messages
var statusCache = map[uint32]string{}
var mux sync.Mutex

const (
	successStatusMessage      = "success"
	keyNotFoundStatusMessage  = "key not found"
	fileNotFoundStatusMessage = "file not found"
	unknownStatusMessage      = "unknown"

	notFoundNTStatus = 3221225524
)

func formatStatus(status uint32, kevt *kevent.Kevent) string {
	if status == 0 {
		return successStatusMessage
	}
	// this status code is return quite often, so we can offload the FormatMessage call
	if status == notFoundNTStatus {
		switch kevt.Category {
		case ktypes.Registry:
			return keyNotFoundStatusMessage
		case ktypes.File:
			return fileNotFoundStatusMessage
		}
	}
	// pick resolved status
	mux.Lock()
	defer mux.Unlock()
	if s, ok := statusCache[status]; ok {
		return s
	}
	var flags uint32 = syscall.FORMAT_MESSAGE_FROM_SYSTEM
	b := make([]uint16, 300)
	n, err := windows.FormatMessage(flags, 0, sys.CodeFromNtStatus(status), 0, b, nil)
	if err != nil {
		return unknownStatusMessage
	}
	// trim terminating \r and \n
	for ; n > 0 && (b[n-1] == '\n' || b[n-1] == '\r'); n-- {
	}

	s := strings.ToLower(string(utf16.Decode(b[:n])))
	statusCache[status] = s

	return s
}
