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

// FileDisposition is the alias for the file disposition modes
type FileDisposition uint8

const (
	// Supersede dictates that if the file already exists, it is replaced with the given file. Otherwise the file with given name is created.
	Supersede FileDisposition = iota
	// Open opens the file if it already exists instead of creating a new file.
	Open
	// Create fails if the file already exists.
	Create
	// OpenIf opens the file if it already exists or creates a new file otherwise.
	OpenIf
	// Overwrite opens and overwrites the file if it already exists. Otherwise it fails.
	Overwrite
	// OverwriteIf opens and overwrites the file is it already exists. Otherwise it creates a new file.
	OverwriteIf
)

// String returns the textual representation of the file disposition.
func (fd FileDisposition) String() string {
	switch fd {
	case Supersede:
		return "supersede"
	case Open:
		return "open"
	case Create:
		return "create"
	case OpenIf:
		return "openif"
	case Overwrite:
		return "overwrite"
	case OverwriteIf:
		return "overwriteif"
	default:
		return "<na>"
	}
}

// FileType is the the type alias for the file type
type FileType uint8

const (
	// File represents the file, volume or hard disk device
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

// FileShareMode designates a type alias for file share mode values
type FileShareMode uint8

const (
	// FileShareRead allows threads to gain read access to the file
	FileShareRead FileShareMode = 1
	// FileShareWrite allows threads to gain write access to the file
	FileShareWrite FileShareMode = 1 << 1
	// FileShareDelete grants threads the possibility to delete files
	FileShareDelete FileShareMode = 1 << 2
)

// String returns user-friendly representation of the file share mask.
func (shareMode FileShareMode) String() string {
	if shareMode == FileShareRead {
		return "r--"
	} else if shareMode == FileShareWrite {
		return "-w-"
	} else if shareMode == FileShareDelete {
		return "--d"
	} else if shareMode&FileShareRead == FileShareRead && shareMode&FileShareWrite == FileShareWrite {
		return "rw-"
	} else if shareMode&FileShareRead == FileShareRead && shareMode&FileShareDelete == FileShareDelete {
		return "r-d"
	} else if shareMode&FileShareWrite == FileShareWrite && shareMode&FileShareDelete == FileShareDelete {
		return "-wd"
	} else if shareMode&FileShareRead == FileShareRead && shareMode&FileShareWrite == FileShareWrite && shareMode&FileShareDelete == FileShareDelete {
		return "rwd"
	}
	return "---"
}
