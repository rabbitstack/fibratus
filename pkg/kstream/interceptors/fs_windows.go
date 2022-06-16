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

package interceptors

import (
	"expvar"
	"sync"

	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
)

var (
	// totalRundownFiles counts the number of opened files
	totalRundownFiles = expvar.NewInt("fs.total.rundown.files")
	// fileObjectMisses computes file object cache misses
	fileObjectMisses     = expvar.NewInt("fs.file.objects.misses")
	fileObjectHandleHits = expvar.NewInt("fs.file.object.handle.hits")
	fileReleaseCount     = expvar.NewInt("fs.file.releases")
)

type fsInterceptor struct {
	// files stores the file metadata indexed by file object
	files map[uint64]*fileInfo
	mux   sync.Mutex
	// devMapper translates DOS device names to regular drive letters
	devMapper fs.DevMapper
	hsnap     handle.Snapshotter
	config    *config.Config

	pendingKevents map[uint64]*kevent.Kevent
}

type fileInfo struct {
	name string
	typ  fs.FileType
}

// fileInfoClass contains the values that specify which structure to use to query or set information for a file object.
// For more information see https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class
var fileInfoClasses = map[uint32]string{
	1:  "Directory",
	2:  "Full Directory",
	3:  "Both Directory",
	4:  "Basic",
	5:  "Standard",
	6:  "Internal",
	7:  "EA",
	8:  "Access",
	9:  "Name",
	10: "Rename",
	11: "Link",
	12: "Names",
	13: "Disposition",
	14: "Position",
	15: "Full EA",
	16: "Mode",
	17: "Alignment",
	18: "All",
	19: "Allocation",
	20: "EOF",
	21: "Alternative Name",
	22: "Stream",
	23: "Pipe",
	24: "Pipe Local",
	25: "Pipe Remote",
	26: "Mailslot Query",
	27: "Mailslot Set",
	28: "Compression",
	29: "Object ID",
	30: "Completion",
	31: "Move Cluster",
	32: "Quota",
	33: "Reparse Point",
	34: "Network Open",
	35: "Attribute Tag",
	36: "Tracking",
	37: "ID Both Directory",
	38: "ID Full Directory",
	39: "Valid Data Length",
	40: "Short Name",
	41: "IO Completion Notification",
	42: "IO Status Block Range",
	43: "IO Priority Hint",
	44: "Sfio Reserve",
	45: "Sfio Volume",
	46: "Hard Link",
	47: "Process IDS Using File",
	48: "Normalized Name",
	49: "Network Physical Name",
	50: "ID Global Tx Directory",
	51: "Is Remote Device",
	52: "Unused",
	53: "Numa Node",
	54: "Standard Link",
	55: "Remote Protocol",
	56: "Rename Bypass Access Check",
	57: "Link Bypass Access Check",
	58: "Volume Name",
	59: "ID",
	60: "ID Extended Directory",
	61: "Replace Completion",
	62: "Hard Link Full ID",
	63: "ID Extended Both Directory",
	64: "Disposition Extended",
	65: "Rename Extended",
	66: "Rename Extended Bypass Access Check",
	67: "Desired Storage",
	68: "Stat",
	69: "Memory Partition",
	70: "Stat LX",
	71: "Case Sensitive",
	72: "Link Extended",
	73: "Link Extended Bypass Access Check",
	74: "Storage Reserve ID",
	75: "Case Sensitive Force Access Check",
}

func infoClassFromID(klass uint32) string {
	class, ok := fileInfoClasses[klass]
	if !ok {
		return "Unknown"
	}
	return class
}

func newFsInterceptor(devMapper fs.DevMapper, hsnap handle.Snapshotter, config *config.Config) KstreamInterceptor {
	interceptor := &fsInterceptor{
		files:          make(map[uint64]*fileInfo),
		pendingKevents: make(map[uint64]*kevent.Kevent),
		devMapper:      devMapper,
		hsnap:          hsnap,
		config:         config,
	}
	return interceptor
}

func (f *fsInterceptor) Intercept(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	switch kevt.Type {
	case ktypes.FileRundown,
		ktypes.FileOpEnd,
		ktypes.CreateFile,
		ktypes.DeleteFile,
		ktypes.CloseFile,
		ktypes.WriteFile,
		ktypes.ReadFile,
		ktypes.RenameFile,
		ktypes.ReleaseFile,
		ktypes.SetFileInformation,
		ktypes.EnumDirectory:

		var fobj uint64
		var err error
		if f.config.Kstream.RawParamParsing {
			fobj, err = kevt.Kparams.GetUint64(kparams.FileObject)
		} else {
			fobj, err = kevt.Kparams.GetHexAsUint64(kparams.FileObject)
		}
		if err != nil && kevt.Type != ktypes.FileOpEnd {
			return kevt, true, err
		}
		// when the file rundown event comes in we store the file info
		// in the map in order to augment the rest of file events
		// that lack the file name field
		if kevt.Type == ktypes.FileRundown {
			filename, err := kevt.Kparams.GetString(kparams.FileName)
			if err != nil {
				return kevt, true, err
			}

			f.mux.Lock()
			defer f.mux.Unlock()
			if _, ok := f.files[fobj]; !ok {
				filename = f.devMapper.Convert(filename)
				totalRundownFiles.Add(1)
				f.files[fobj] = &fileInfo{name: filename, typ: fs.GetFileType(filename, 0)}
			}

			return kevt, false, nil
		}
		// we'll update event's thread identifier with the one
		// that's involved in the file system operation
		kevt.Tid, err = kevt.Kparams.GetUint32(kparams.ThreadID)
		if err != nil {
			// tid is sometimes represented in hex format
			kevt.Tid, _ = kevt.Kparams.GetHexAsUint32(kparams.ThreadID)
		}

		switch kevt.Type {
		case ktypes.CreateFile:
			// we defer the processing of the CreateFile event until we get
			// the matching FileOpEnd event. This event contains the operation
			// that was done on behalf of the file, e.g. create or open.
			var irp uint64
			var err error
			if f.config.Kstream.RawParamParsing {
				irp, err = kevt.Kparams.GetUint64(kparams.FileIrpPtr)
			} else {
				irp, err = kevt.Kparams.GetHexAsUint64(kparams.FileIrpPtr)
			}
			if err != nil {
				return kevt, true, err
			}
			f.pendingKevents[irp] = kevt
			return kevt, false, kerrors.ErrCancelUpstreamKevent

		case ktypes.FileOpEnd:
			// get the CreateFile pending event by IRP identifier
			var irp uint64
			var extraInfo uint8
			var err error
			if f.config.Kstream.RawParamParsing {
				irp, err = kevt.Kparams.GetUint64(kparams.FileIrpPtr)
				if err != nil {
					return kevt, true, err
				}
				v, err := kevt.Kparams.GetUint64(kparams.FileExtraInfo)
				if err != nil {
					return kevt, true, err
				}
				extraInfo = uint8(v)
			} else {
				irp, err = kevt.Kparams.GetHexAsUint64(kparams.FileIrpPtr)
				if err != nil {
					return kevt, true, err
				}
				extraInfo, err = kevt.Kparams.GetHexAsUint8(kparams.FileExtraInfo)
				if err != nil {
					return kevt, true, err
				}
			}
			fkevt, ok := f.pendingKevents[irp]
			if !ok {
				return kevt, true, kerrors.ErrCancelUpstreamKevent
			}
			fkevt.Kparams.Append(kparams.FileExtraInfo, kparams.Uint8, extraInfo)
			delete(f.pendingKevents, irp)
			if err := f.processCreateFile(fkevt); err != nil {
				return kevt, true, err
			}
			return fkevt, false, nil

		case ktypes.ReleaseFile:
			fileReleaseCount.Add(1)
			var fileKey uint64
			var err error
			// delete both, the file object and the file key from files map
			if f.config.Kstream.RawParamParsing {
				fileKey, err = kevt.Kparams.GetUint64(kparams.FileKey)
			} else {
				fileKey, err = kevt.Kparams.GetHexAsUint64(kparams.FileKey)
			}
			f.mux.Lock()
			defer f.mux.Unlock()
			if err == nil {
				delete(f.files, fileKey)
			}
			delete(f.files, fobj)

		case ktypes.DeleteFile, ktypes.RenameFile,
			ktypes.CloseFile, ktypes.ReadFile,
			ktypes.WriteFile, ktypes.SetFileInformation, ktypes.EnumDirectory:
			var fileKey uint64
			var err error
			if f.config.Kstream.RawParamParsing {
				fileKey, err = kevt.Kparams.GetUint64(kparams.FileKey)
			} else {
				fileKey, err = kevt.Kparams.GetHexAsUint64(kparams.FileKey)
			}
			if err != nil {
				return kevt, true, err
			}

			// attempt to get the file by file key. If there is no such file referenced
			// by the file key, then try to fetch it by file object. Even if file object
			// references fails, we search in the file handles for such file
			f.mux.Lock()
			defer f.mux.Unlock()
			fileinfo, ok := f.files[fileKey]
			if !ok {
				fileinfo, ok = f.files[fobj]
				if !ok {
					// look in the system handles for file objects
					var h htypes.Handle
					h, ok = f.hsnap.FindByObject(fobj)
					if ok && h.Type == handle.File {
						fileObjectHandleHits.Add(1)
						f.files[fobj] = &fileInfo{name: h.Name, typ: fs.GetFileType(h.Name, 0)}
					}
				}
			}

			// ignore object misses that are produced by CloseFile
			if !ok && kevt.Type != ktypes.CloseFile {
				fileObjectMisses.Add(1)
			}

			if kevt.Type == ktypes.DeleteFile {
				delete(f.files, fobj)
			}

			if kevt.Type == ktypes.SetFileInformation || kevt.Type == ktypes.EnumDirectory || kevt.Type == ktypes.RenameFile || kevt.Type == ktypes.DeleteFile {
				// assign a human-readable information class from the class ID
				infoClassID, err := kevt.Kparams.GetUint32(kparams.FileInfoClass)
				if err == nil {
					kevt.Kparams.Remove(kparams.FileInfoClass)
					kevt.Kparams.Append(kparams.FileInfoClass, kparams.AnsiString, infoClassFromID(infoClassID))
				}
				kevt.Kparams.Remove(kparams.FileExtraInfo)
			}

			if kevt.Type == ktypes.EnumDirectory {
				// the file key kparam contains the reference to the directory name
				var fileKey uint64
				var err error
				if f.config.Kstream.RawParamParsing {
					fileKey, err = kevt.Kparams.GetUint64(kparams.FileKey)
				} else {
					fileKey, err = kevt.Kparams.GetHexAsUint64(kparams.FileKey)
				}
				if err != nil {
					kevt.Kparams.Remove(kparams.FileKey)
					removeKparams(kevt)
					return kevt, true, nil
				}
				kevt.Kparams.Remove(kparams.FileKey)
				fileinfo, ok := f.files[fileKey]
				if ok && fileinfo != nil {
					kevt.Kparams.Append(kparams.FileDirectory, kparams.UnicodeString, fileinfo.name)
				}
			}

			removeKparams(kevt)

			if err := f.appendKparams(fileinfo, kevt); err != nil {
				return kevt, true, err
			}
		}
	default:
		return kevt, true, nil
	}

	return kevt, true, nil
}

func (*fsInterceptor) Name() InterceptorType { return Fs }
func (f *fsInterceptor) Close()              {}

func (f *fsInterceptor) getFileInfo(name string, opts uint32) *fileInfo {
	return &fileInfo{name: name, typ: fs.GetFileType(name, opts)}
}

func (f *fsInterceptor) processCreateFile(kevt *kevent.Kevent) error {
	var fobj uint64
	var extraInfo uint8
	var err error
	if f.config.Kstream.RawParamParsing {
		fobj, err = kevt.Kparams.GetUint64(kparams.FileObject)
		if err != nil {
			return err
		}
	} else {
		fobj, err = kevt.Kparams.GetHexAsUint64(kparams.FileObject)
		if err != nil {
			return err
		}
	}

	extraInfo, err = kevt.Kparams.GetUint8(kparams.FileExtraInfo)
	if err != nil {
		return err
	}

	// delete raw event parameters
	kevt.Kparams.Remove(kparams.FileExtraInfo)
	// append human-readable file operation param
	kevt.Kparams.Append(kparams.FileOperation, kparams.Enum, fs.FileDisposition(extraInfo))

	filename, err := kevt.Kparams.GetString(kparams.FileName)
	if err != nil {
		return err
	}
	filename = f.devMapper.Convert(filename)
	if err := kevt.Kparams.Set(kparams.FileName, filename, kparams.UnicodeString); err != nil {
		return err
	}
	// figure out the file share mask that determines
	// the type of share access that the caller thread
	// would like to grant to other threads
	mask, err := kevt.Kparams.GetUint32(kparams.FileShareMask)
	if err != nil {
		return err
	}
	if err := kevt.Kparams.Set(kparams.FileShareMask, fs.FileShareMode(mask), kparams.Enum); err != nil {
		return err
	}
	// try to get extended file info. If the file object is already
	// present in the map, we'll reuse the existing file information
	f.mux.Lock()
	defer f.mux.Unlock()
	fileinfo, ok := f.files[fobj]
	if !ok {
		opts, _ := kevt.Kparams.GetUint32(kparams.FileCreateOptions)
		opts &= 0xFFFFFF

		fileinfo = f.getFileInfo(filename, opts)
		// file type couldn't be resolved so we perform the lookup
		// in system handles to determine whether file object is
		// a directory
		if fileinfo.typ == fs.Unknown {
			fileinfo.typ = f.findDirHandle(fobj)
		}
		kevt.Kparams.Append(kparams.FileType, kparams.AnsiString, fileinfo.typ.String())

		f.files[fobj] = fileinfo
	}

	removeKparams(kevt)

	return f.appendKparams(fileinfo, kevt)
}

func (f *fsInterceptor) findDirHandle(fobj uint64) fs.FileType {
	fhandle, ok := f.hsnap.FindByObject(fobj)
	if !ok || fhandle.Type != handle.File {
		return fs.Unknown
	}
	if fhandle.MD == nil {
		return fs.Unknown
	}
	md, ok := fhandle.MD.(*htypes.FileInfo)
	if ok && md.IsDirectory {
		return fs.Directory
	}
	return fs.Unknown
}

func (f *fsInterceptor) appendKparams(fileinfo *fileInfo, kevt *kevent.Kevent) error {
	if kevt.Type == ktypes.EnumDirectory {
		return nil
	}
	if fileinfo == nil {
		if kevt.Type != ktypes.CreateFile {
			kevt.Kparams.Append(kparams.FileName, kparams.UnicodeString, kparams.NA)
		}
		return nil
	}
	if fileinfo.typ != fs.Unknown {
		kevt.Kparams.Append(kparams.FileType, kparams.AnsiString, fileinfo.typ.String())
	}
	if kevt.Type != ktypes.CreateFile {
		kevt.Kparams.Append(kparams.FileName, kparams.UnicodeString, fileinfo.name)
	}
	return nil
}

// removeKparams removes unwanted kparams, either because they are already present in kevent
// canonical attributes or are not very useful.
func removeKparams(kevt *kevent.Kevent) {
	if kevt.Kparams.Contains(kparams.ProcessID) {
		kevt.Kparams.Remove(kparams.ProcessID)
	}
	if kevt.Kparams.Contains(kparams.ThreadID) {
		kevt.Kparams.Remove(kparams.ThreadID)
	}
	if kevt.Kparams.Contains(kparams.FileCreateOptions) {
		kevt.Kparams.Remove(kparams.FileCreateOptions)
	}
	if kevt.Kparams.Contains(kparams.FileKey) {
		kevt.Kparams.Remove(kparams.FileKey)
	}
}
