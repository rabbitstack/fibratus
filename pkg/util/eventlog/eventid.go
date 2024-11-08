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

package eventlog

import "golang.org/x/sys/windows"

// EventID produces the eventlog event identifier from the given
// severity and event code. The format of the event id
// integer is described by the next layout:
//
//	3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//	1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//
// +---+-+-+-----------------------+-------------------------------+
// |Sev|C|R|     Facility          |               Code            |
// +---+-+-+-----------------------+-------------------------------+
func EventID(etype, code uint16) uint32 {
	var id uint32

	// severity
	switch etype {
	case windows.EVENTLOG_INFORMATION_TYPE:
		id = uint32(0)<<30 | uint32(1)<<29
	case windows.EVENTLOG_WARNING_TYPE:
		id = uint32(1)<<30 | uint32(0)<<29
	case windows.EVENTLOG_ERROR_TYPE:
		id = uint32(1)<<30 | uint32(1)<<29
	default:
		id = uint32(0)<<30 | uint32(1)<<29
	}
	// customer bit
	id |= uint32(0) << 28
	// reserved bit
	id |= uint32(0) << 27
	// facility
	id |= uint32(0) << 15
	// code
	id |= uint32(code)

	return id
}
