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

// FileAttr represents a type alias for the file attribute enumeration.
type FileAttr uint32

const (
	// FileReadOnly represents file that is read-only. Processes can read the file, but cannot write to it or delete it.
	// This attribute is not honored on directories.
	FileReadOnly FileAttr = 0x00000001
	// FileHidden designates a file or directory that is hidden, i.e. it is not included in an ordinary directory listing.
	FileHidden FileAttr = 0x00000002
	// FileSystem is a file or directory that the operating system uses a part of, or uses exclusively.
	FileSystem FileAttr = 0x00000004
	// FileOldDosVolID is unused
	FileOldDosVolID FileAttr = 0x00000008
	// FileDirectory indicates that the file is a directory.
	FileDirectory FileAttr = 0x00000010
	// FileArchive denotes a file or directory that is an archive file or directory. Applications typically use this attribute to mark files for backup or removal.
	FileArchive FileAttr = 0x00000020
	// FileDevice attribute is reserved for system use.
	FileDevice FileAttr = 0x00000040
	// FileNormal is a file that does not have other attributes set. This attribute is valid only when used alone.
	FileNormal FileAttr = 0x00000080
	// FileTemporary denotes files that are used for temporary storage.
	FileTemporary = 0x00000100
	// FileSparse denotes a sparse file. Spare files can optimize disk usage as the system does not allocate disk space for the file regions with sparse data.
	FileSparse = 0x00000200
	// FileReparsePoint represents a file or directory that has an associated reparse point, or a file that is a symbolic link.
	FileReparsePoint FileAttr = 0x00000400
	// FileCompressed represents a file or a directory that is compressed.
	FileCompressed FileAttr = 0x00000800
	// FileOffline represents data of a file is not available immediately. This attribute indicates that the file data is physically moved to offline storage.
	FileOffline FileAttr = 0x00001000
	// FileNotContentIndexed is a file or directory is not to be indexed by the content indexing service.
	FileNotContentIndexed = 0x00002000
	// FileEncrypted represents a file or a directory that is encrypted
	FileEncrypted FileAttr = 0x00004000
	// FileIntegrityStream is the directory or user data stream is configured with integrity (only supported on ReFS volumes).
	// It is not included in an ordinary directory listing.
	FileIntegrityStream FileAttr = 0x00008000
	// FileVirtual is reserved for system use.
	FileVirtual FileAttr = 0x00010000
	// FileNoScrubData represents user data stream not to be read by the background data integrity scanner (AKA scrubber).
	// When set on a directory it only provides inheritance. This flag is only supported on Storage Spaces and ReFS volumes
	FileNoScrubData FileAttr = 0x00020000
	// FileRecallOpen attribute only appears in directory enumeration classes (FILE_DIRECTORY_INFORMATION,
	// FILE_BOTH_DIR_INFORMATION, etc.). When this attribute is set, it means that the file or directory has no physical
	// representation on the local system; the item is virtual
	FileRecallOpen FileAttr = 0x00040000
	// FileRecallAccess means that the file or directory is not fully present locally.
	// For a file that means that not all of its data is on local storage (e.g. it may be sparse with some data still in
	// remote storage). For a directory it means that some of the directory contents are being virtualized from another
	// location.
	FileRecallAccess FileAttr = 0x400000
	// FilePinned indicates user intent that the file or directory should be kept fully present locally
	// even when not being actively accessed. This attribute is for use with hierarchical storage management software.
	FilePinned FileAttr = 0x80000
	// FileUnpinned indicates that the file or directory should not be kept fully present locally except
	// when being actively accessed. This attribute is for use with hierarchical storage management software.
	FileUnpinned FileAttr = 0x100000
)

// FileAttr returns human-readable file attribute name.
func (fa FileAttr) String() string {
	switch fa {
	case FileReadOnly:
		return "readonly"
	case FileHidden:
		return "hidden"
	case FileSystem:
		return "system"
	case FileDirectory:
		return "directory"
	case FileArchive:
		return "archive"
	case FileCompressed:
		return "compressed"
	case FileEncrypted:
		return "encrypted"
	case FileReparsePoint:
		return "junction"
	case FileSparse:
		return "sparse"
	case FileTemporary:
		return "temporary"
	case FileDevice:
		return "device"
	case FileNormal:
		return "normal"
	case FileOffline:
		return "offline"
	case FileNotContentIndexed:
		return "unindexed"
	case FileIntegrityStream:
		return "stream"
	case FileVirtual:
		return "virtual"
	case FileNoScrubData:
		return "noscrub"
	case FileRecallOpen:
		return "recallopen"
	case FileRecallAccess:
		return "recallaccess"
	case FilePinned:
		return "pinned"
	case FileUnpinned:
		return "unpinned"
	default:
		return "unknown"
	}
}
