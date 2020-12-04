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

// FileAttr represents a type alias for the file attribute enumeration.
type FileAttr uint32

const (
	// FileDirectory indicates that the file is a directory.
	FileDirectory FileAttr = 0x10
	// FileArchive denotes a file or directory that is an archive file or directory. Applications typically use this attribute to mark files for backup or removal.
	FileArchive FileAttr = 0x20
	// FileCompressed represents a file or a directory that is compressed.
	FileCompressed FileAttr = 0x800
	// FileEncrypted represents a file or a directory that is encrypted
	FileEncrypted FileAttr = 0x4000
	// FileHidden designates a file or directory that is hidden, i.e. it is not included in an ordinary directory listing.
	FileHidden FileAttr = 0x2
	// FileReparsePoint represents a file or directory that has an associated reparse point, or a file that is a symbolic link.
	FileReparsePoint FileAttr = 0x400
	// FileSparse denotes a sparse file. Spares files can optimize disk usage as the system does not allocate disk space for the file regions with sparse data.
	FileSparse = 0x200
	// FileTemporary denotes files that are used for temporary storage.
	FileTemporary = 0x100
)

// FileAttr returns human-readable file attribute name.
func (fa FileAttr) String() string {
	switch fa {
	case FileDirectory:
		return "directory"
	case FileArchive:
		return "archive"
	case FileCompressed:
		return "compressed"
	case FileEncrypted:
		return "encrypted"
	case FileHidden:
		return "hidden"
	case FileReparsePoint:
		return "junction"
	case FileSparse:
		return "sparse"
	case FileTemporary:
		return "temporary"
	default:
		return "unknown"
	}
}
