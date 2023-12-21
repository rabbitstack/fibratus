//go:build windows
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

package fs

import "golang.org/x/sys/windows"

// FileCreateDispositions is the mapping between the file create disposition and its symbolical name.
var FileCreateDispositions = map[uint32]string{
	uint32(windows.FILE_SUPERSEDE):    "SUPERSEDE",
	uint32(windows.FILE_OPEN):         "OPEN",
	uint32(windows.FILE_CREATE):       "CREATE",
	uint32(windows.FILE_OPEN_IF):      "OPEN_IF",
	uint32(windows.FILE_OVERWRITE):    "OVERWRITE",
	uint32(windows.FILE_OVERWRITE_IF): "OVERWRITE_IF",
}

// FileType is the type alias for the file type
type FileType uint8

const (
	// Regular represents the file, volume or hard disk device
	Regular FileType = iota
	// Directory represents the directory
	Directory
	// Pipe represent the pipe
	Pipe
	// Console denotes the standard output stream
	Console
	// Mailslot denotes a mail slot file
	Mailslot
	// Other is the file type different from listed above
	Other
	// Unknown is the unknown file type
	Unknown
)

// String returns the textual representation of the file type.
func (typ FileType) String() string {
	switch typ {
	case Regular:
		return "file"
	case Directory:
		return "directory"
	case Pipe:
		return "pipe"
	case Console:
		return "console"
	case Mailslot:
		return "mailslot"
	case Other:
		return "other"
	default:
		return "unknown"
	}
}

// FileTypes represents the mapping of file type identifiers to their string values.
var FileTypes = map[uint32]string{
	uint32(Regular):   "File",
	uint32(Directory): "Directory",
	uint32(Pipe):      "Pipe",
	uint32(Console):   "Console",
	uint32(Mailslot):  "Mailslot",
	uint32(Other):     "Other",
}
