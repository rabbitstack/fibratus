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
	hsnap handle.Snapshotter

	pendingKevents map[uint64]*kevent.Kevent
}

type fileInfo struct {
	name string
	typ  fs.FileType
}

func newFsInterceptor(hsnap handle.Snapshotter) KstreamInterceptor {
	interceptor := &fsInterceptor{
		files:          make(map[uint64]*fileInfo),
		pendingKevents: make(map[uint64]*kevent.Kevent),
		hsnap:          hsnap,
	}
	return interceptor
}

func (f *fsInterceptor) Intercept(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if kevt.Category == ktypes.File {
		return kevt, false, f.processEvent(kevt)
	}
	return kevt, true, nil
}

func (*fsInterceptor) Name() InterceptorType { return Fs }
func (f *fsInterceptor) Close()              {}

func (f *fsInterceptor) getFileInfo(name string, opts uint32) *fileInfo {
	return &fileInfo{name: name, typ: fs.GetFileType(name, opts)}
}

func (f *fsInterceptor) processEvent(kevt *kevent.Kevent) error {
	fobj, err := kevt.Kparams.GetUint64(kparams.FileObject)
	if err != nil && kevt.Type != ktypes.FileOpEnd {
		return err
	}
	// we'll update event's thread identifier with the one
	// that's involved in the file system operation
	kevt.Tid, _ = kevt.Kparams.GetTid()

	switch kevt.Type {
	case ktypes.FileRundown:
		// when the file rundown event comes in we store the file info
		// in internal state in order to augment the rest of file events
		// that lack the file name field
		filename := kevt.GetParamAsString(kparams.FileName)
		f.mux.Lock()
		defer f.mux.Unlock()
		if _, ok := f.files[fobj]; !ok {
			totalRundownFiles.Add(1)
			f.files[fobj] = &fileInfo{name: filename, typ: fs.GetFileType(filename, 0)}
		}
	case ktypes.CreateFile:
		// we defer the processing of the CreateFile event until we get
		// the matching FileOpEnd event. This event contains the operation
		// that was done on behalf of the file, e.g. create or open.
		irp, err := kevt.Kparams.GetUint64(kparams.FileIrpPtr)
		if err != nil {
			return err
		}
		f.pendingKevents[irp] = kevt
		return kerrors.ErrCancelUpstreamKevent
	case ktypes.FileOpEnd:
		// get the CreateFile pending event by IRP identifier
		// and fetch the file create disposition value
		irp, err := kevt.Kparams.GetUint64(kparams.FileIrpPtr)
		if err != nil {
			return err
		}
		extraInfo, err := kevt.Kparams.GetUint64(kparams.FileExtraInfo)
		if err != nil {
			return err
		}
		fkevt, ok := f.pendingKevents[irp]
		if !ok {
			return kerrors.ErrCancelUpstreamKevent
		}
		// resolve the status of the file operation
		status, err := kevt.Kparams.GetUint32(kparams.NTStatus)
		if err == nil {
			fkevt.AppendParam(kparams.NTStatus, kparams.Status, status)
		}
		delete(f.pendingKevents, irp)

		// append file create disposition
		kevt.AppendParam(kparams.FileOperation, kparams.Enum, uint32(extraInfo), kevent.WithEnum(fs.FileCreateDispositions))

		// try to get extended file info. If the file object is already
		// present in the map, we'll reuse the existing file information
		f.mux.Lock()
		defer f.mux.Unlock()
		fileinfo, ok := f.files[fobj]
		if !ok {
			opts, _ := kevt.Kparams.GetUint32(kparams.FileCreateOptions)
			opts &= 0xFFFFFF

			filename := kevt.GetParamAsString(kparams.FileName)
			fileinfo = f.getFileInfo(filename, opts)
			// file type couldn't be resolved, so we perform the lookup
			// in system handles to determine whether file object is
			// a directory
			if fileinfo.typ == fs.Unknown {
				fileinfo.typ = f.findDirHandle(fobj)
			}
			kevt.AppendParam(kparams.FileType, kparams.AnsiString, fileinfo.typ.String())
			f.files[fobj] = fileinfo
		}
		// delete raw event parameters
		kevt.Kparams.Remove(kparams.FileExtraInfo)
		kevt.Kparams.Remove(kparams.FileCreateOptions)
	case ktypes.ReleaseFile:
		fileReleaseCount.Add(1)
		// delete both, the file object and the file key from files map
		fileKey, err := kevt.Kparams.GetUint64(kparams.FileKey)
		f.mux.Lock()
		defer f.mux.Unlock()
		if err == nil {
			delete(f.files, fileKey)
		}
		delete(f.files, fobj)
	case ktypes.DeleteFile, ktypes.RenameFile,
		ktypes.CloseFile, ktypes.ReadFile,
		ktypes.WriteFile, ktypes.SetFileInformation, ktypes.EnumDirectory:
		fileKey, err := kevt.Kparams.GetUint64(kparams.FileKey)
		if err != nil {
			return err
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

		if kevt.Type == ktypes.EnumDirectory {
			// the file key parameter contains the reference to the directory name
			fileKey, err := kevt.Kparams.GetUint64(kparams.FileKey)
			if err != nil {
				kevt.Kparams.Remove(kparams.FileKey)
				return err
			}
			kevt.Kparams.Remove(kparams.FileKey)
			fileinfo, ok := f.files[fileKey]
			if ok && fileinfo != nil {
				kevt.AppendParam(kparams.FileDirectory, kparams.FilePath, fileinfo.name)
			}
			break
		}

		if fileinfo != nil {
			if fileinfo.typ != fs.Unknown {
				kevt.AppendParam(kparams.FileType, kparams.AnsiString, fileinfo.typ.String())
			}
			kevt.AppendParam(kparams.FileName, kparams.FilePath, fileinfo.name)
		}
	}
	return nil
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
