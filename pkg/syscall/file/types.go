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

package file

import "syscall"

// AttributeData contains meta information about a file.
type AttributeData struct {
	// FileAttributes represents the file attributes.
	FileAttributes uint32
	// CreationTime specifies when a file or directory is created. If the underlying file system does not support creation time, this member is zero.
	CreationTime syscall.Filetime
	// LastAccessTime for a file, the structure specifies the last time that a file is read from or written to.
	// For a directory, the structure specifies when the directory is created. For both files and directories,
	// the specified date is correct, but the time of day is always set to midnight. If the underlying file
	// system does not support the last access time, this member is zero (0).
	LastAccessTime syscall.Filetime
	// LastWriteTime for a file, the structure specifies the last time that a file is written to. For a directory,
	// the structure specifies when the directory is created. If the underlying file system does not support the last write time,
	// this member is zero (0).
	LastWriteTime syscall.Filetime
	// FileSizeHigh high-order part of the file size.
	FileSizeHigh uint32
	// FileSizeLow low-order part of the file size.
	FileSizeLow uint32
}

// DevInfo provides file system device information about the type of device object associated with a file object.
type DevInfo struct {
	// Type designates the type of underlying device.
	Type uint32
	// Characteristics represents device characteristics.
	Characteristcs uint32
}

type ioStatusBlock struct {
	status, information uintptr
}
