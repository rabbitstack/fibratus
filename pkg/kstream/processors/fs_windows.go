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

package processors

import (
	"expvar"
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

type fsProcessor struct {
	// files stores the file metadata indexed by file object
	files map[uint64]*fileInfo
	hsnap handle.Snapshotter
	// irps contains a mapping between the IRP and the CreateFile events
	irps map[uint64]*kevent.Kevent
}

type fileInfo struct {
	name string
	typ  fs.FileType
}

func newFsProcessor(hsnap handle.Snapshotter) Processor {
	interceptor := &fsProcessor{
		files: make(map[uint64]*fileInfo),
		irps:  make(map[uint64]*kevent.Kevent),
		hsnap: hsnap,
	}
	return interceptor
}

func (f *fsProcessor) ProcessEvent(kevt *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if kevt.Category == ktypes.File {
		kevt, err := f.processEvent(kevt)
		kevt.Tid, _ = kevt.Kparams.GetTid()
		return kevt, false, err
	}
	return kevt, true, nil
}

func (*fsProcessor) Name() ProcessorType { return Fs }
func (f *fsProcessor) Close()            {}

func (f *fsProcessor) getFileInfo(name string, opts uint32) *fileInfo {
	return &fileInfo{name: name, typ: fs.GetFileType(name, opts)}
}

func (f *fsProcessor) processEvent(kevt *kevent.Kevent) (*kevent.Kevent, error) {
	switch kevt.Type {
	case ktypes.FileRundown:
		// when the file rundown event comes in we store the file info
		// in internal state in order to augment the rest of file events
		// that lack the file name field
		filename := kevt.GetParamAsString(kparams.FileName)
		fileObject := kevt.Kparams.MustGetUint64(kparams.FileObject)
		if _, ok := f.files[fileObject]; !ok {
			totalRundownFiles.Add(1)
			f.files[fileObject] = &fileInfo{name: filename, typ: fs.GetFileType(filename, 0)}
		}
	case ktypes.CreateFile:
		// we defer the processing of the CreateFile event until we get
		// the matching FileOpEnd event. This event contains the operation
		// that was done on behalf of the file, e.g. create or open.
		irp := kevt.Kparams.MustGetUint64(kparams.FileIrpPtr)
		f.irps[irp] = kevt
		return kevt, kerrors.ErrCancelUpstreamKevent
	case ktypes.FileOpEnd:
		// get the CreateFile pending event by IRP identifier
		// and fetch the file create disposition value
		var (
			irp    = kevt.Kparams.MustGetUint64(kparams.FileIrpPtr)
			dispo  = kevt.Kparams.MustGetUint64(kparams.FileExtraInfo)
			status = kevt.Kparams.MustGetUint32(kparams.NTStatus)
		)
		fevt, ok := f.irps[irp]
		if !ok {
			return kevt, nil
		}
		kevt = fevt
		delete(f.irps, irp)
		fileObject := kevt.Kparams.MustGetUint64(kparams.FileObject)
		// try to get extended file info. If the file object is already
		// present in the map, we'll reuse the existing file information
		fileinfo, ok := f.files[fileObject]
		if !ok {
			opts := kevt.Kparams.MustGetUint32(kparams.FileCreateOptions)
			opts &= 0xFFFFFF

			filename := kevt.GetParamAsString(kparams.FileName)
			fileinfo = f.getFileInfo(filename, opts)
			// file type couldn't be resolved, so we perform the lookup
			// in system handles to determine whether file object is
			// a directory
			if fileinfo.typ == fs.Unknown {
				fileinfo.typ = f.findDirHandle(fileObject)
			}
			f.files[fileObject] = fileinfo
		}
		kevt.AppendParam(kparams.NTStatus, kparams.Status, status)
		kevt.AppendParam(kparams.FileType, kparams.Enum, uint32(fileinfo.typ), kevent.WithEnum(fs.FileTypes))
		kevt.AppendParam(kparams.FileOperation, kparams.Enum, uint32(dispo), kevent.WithEnum(fs.FileCreateDispositions))
		return kevt, nil
	case ktypes.ReleaseFile:
		fileReleaseCount.Add(1)
		// delete both, the file object and the file key from files map
		fileKey := kevt.Kparams.MustGetUint64(kparams.FileKey)
		fobj := kevt.Kparams.MustGetUint64(kparams.FileObject)
		delete(f.files, fileKey)
		delete(f.files, fobj)
	default:
		fileKey := kevt.Kparams.MustGetUint64(kparams.FileKey)
		fileObject := kevt.Kparams.MustGetUint64(kparams.FileObject)
		// attempt to get the file by file key. If there is no such file referenced
		// by the file key, then try to fetch it by file object. Even if file object
		// references fails, we search in the file handles for such file
		fileinfo := f.findFile(fileKey, fileObject)
		// ignore object misses that are produced by CloseFile
		if fileinfo == nil && kevt.IsCloseFile() {
			fileObjectMisses.Add(1)
		}
		if kevt.IsDeleteFile() {
			delete(f.files, fileObject)
		}
		if kevt.IsEnumDirectory() {
			// the file key parameter contains the reference to the directory name
			fileKey, err := kevt.Kparams.GetUint64(kparams.FileKey)
			if err != nil {
				return kevt, err
			}
			fileinfo, ok := f.files[fileKey]
			if ok && fileinfo != nil {
				kevt.AppendParam(kparams.FileDirectory, kparams.FilePath, fileinfo.name)
			}
			break
		}
		if fileinfo != nil {
			if fileinfo.typ != fs.Unknown {
				kevt.AppendParam(kparams.FileType, kparams.Enum, uint32(fileinfo.typ), kevent.WithEnum(fs.FileTypes))
			}
			kevt.AppendParam(kparams.FileName, kparams.FilePath, fileinfo.name)
		}
	}
	return kevt, nil
}

func (f *fsProcessor) findFile(fileKey, fileObject uint64) *fileInfo {
	fileinfo, ok := f.files[fileKey]
	if ok {
		return fileinfo
	}
	fileinfo, ok = f.files[fileObject]
	if ok {
		return fileinfo
	}
	// look in the system handles for file objects
	var h htypes.Handle
	h, ok = f.hsnap.FindByObject(fileObject)
	if ok && h.Type == handle.File {
		fileObjectHandleHits.Add(1)
		return &fileInfo{name: h.Name, typ: fs.GetFileType(h.Name, 0)}
	}
	return nil
}

func (f *fsProcessor) findDirHandle(fileObject uint64) fs.FileType {
	h, ok := f.hsnap.FindByObject(fileObject)
	if !ok || h.Type != handle.File {
		return fs.Unknown
	}
	if h.MD == nil {
		return fs.Unknown
	}
	md, ok := h.MD.(*htypes.FileInfo)
	if ok && md.IsDirectory {
		return fs.Directory
	}
	return fs.Unknown
}
