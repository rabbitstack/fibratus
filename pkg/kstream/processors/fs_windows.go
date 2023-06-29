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
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
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
	files map[uint64]*FileInfo
	hsnap handle.Snapshotter
	// irps contains a mapping between the IRP (I/O request packet) and CreateFile events
	irps map[uint64]*kevent.Kevent

	devMapper       fs.DevMapper
	devPathResolver fs.DevPathResolver
}

// FileInfo stores file information obtained from event state.
type FileInfo struct {
	Name string
	Type fs.FileType
}

func newFsProcessor(hsnap handle.Snapshotter, devMapper fs.DevMapper, devPathResolver fs.DevPathResolver) Processor {
	return &fsProcessor{
		files:           make(map[uint64]*FileInfo),
		irps:            make(map[uint64]*kevent.Kevent),
		hsnap:           hsnap,
		devMapper:       devMapper,
		devPathResolver: devPathResolver,
	}
}

func (f *fsProcessor) ProcessEvent(e *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if e.Category == ktypes.File {
		evt, err := f.processEvent(e)
		return evt, false, err
	}
	return e, true, nil
}

func (*fsProcessor) Name() ProcessorType { return Fs }
func (f *fsProcessor) Close()            {}

func (f *fsProcessor) getFileInfo(name string, opts uint32) *FileInfo {
	return &FileInfo{Name: name, Type: fs.GetFileType(name, opts)}
}

func (f *fsProcessor) processEvent(e *kevent.Kevent) (*kevent.Kevent, error) {
	switch e.Type {
	case ktypes.FileRundown:
		// when the file rundown event comes in we store the file info
		// in internal state in order to augment the rest of file events
		// that lack the file name field
		filename := e.GetParamAsString(kparams.FileName)
		fileObject, err := e.Kparams.GetUint64(kparams.FileObject)
		if err != nil {
			return nil, err
		}
		if _, ok := f.files[fileObject]; !ok {
			totalRundownFiles.Add(1)
			f.files[fileObject] = &FileInfo{Name: filename, Type: fs.GetFileType(filename, 0)}
		}
	case ktypes.MapFileRundown:
		// currently just forward mapped file rundown events
		return e, nil
	case ktypes.CreateFile:
		// we defer the processing of the CreateFile event until we get
		// the matching FileOpEnd event. This event contains the operation
		// that was done on behalf of the file, e.g. create or open.
		irp := e.Kparams.MustGetUint64(kparams.FileIrpPtr)
		e.WaitEnqueue = true
		f.irps[irp] = e
	case ktypes.FileOpEnd:
		// get the CreateFile pending event by IRP identifier
		// and fetch the file create disposition value
		var (
			irp    = e.Kparams.MustGetUint64(kparams.FileIrpPtr)
			dispo  = e.Kparams.MustGetUint64(kparams.FileExtraInfo)
			status = e.Kparams.MustGetUint32(kparams.NTStatus)
		)
		ev, ok := f.irps[irp]
		if !ok {
			return e, nil
		}
		delete(f.irps, irp)
		// reset the wait status to allow passage of this event to
		// the aggregator queue. Additionally, append params to it
		ev.WaitEnqueue = false
		fileObject := ev.Kparams.MustGetUint64(kparams.FileObject)
		// try to get extended file info. If the file object is already
		// present in the map, we'll reuse the existing file information
		fileinfo, ok := f.files[fileObject]
		if !ok {
			opts := ev.Kparams.MustGetUint32(kparams.FileCreateOptions)
			opts &= 0xFFFFFF
			filename := ev.GetParamAsString(kparams.FileName)
			fileinfo = f.getFileInfo(filename, opts)
			f.files[fileObject] = fileinfo
		}
		f.devPathResolver.AddPath(ev.GetParamAsString(kparams.FileName))
		ev.AppendParam(kparams.NTStatus, kparams.Status, status)
		if fileinfo.Type != fs.Unknown {
			ev.AppendEnum(kparams.FileType, uint32(fileinfo.Type), fs.FileTypes)
		}
		ev.AppendEnum(kparams.FileOperation, uint32(dispo), fs.FileCreateDispositions)
		return ev, nil
	case ktypes.ReleaseFile, ktypes.UnmapViewFile:
		var fileObject uint64
		fileReleaseCount.Add(1)
		// delete both, the file object and the file key from files map
		fileKey := e.Kparams.MustGetUint64(kparams.FileKey)
		if !e.IsUnmapViewFile() {
			fileObject = e.Kparams.MustGetUint64(kparams.FileObject)
		}
		fileinfo := f.findFile(fileKey, fileObject)
		if fileinfo != nil && e.IsUnmapViewFile() {
			e.AppendParam(kparams.FileName, kparams.FilePath, fileinfo.Name)
		}
		delete(f.files, fileKey)
		delete(f.files, fileObject)
	default:
		var fileObject uint64
		fileKey := e.Kparams.MustGetUint64(kparams.FileKey)
		if !e.IsMapViewFile() {
			fileObject = e.Kparams.MustGetUint64(kparams.FileObject)
		}
		// attempt to get the file by file key. If there is no such file referenced
		// by the file key, then try to fetch it by file object. Even if file object
		// references fails, we search in the file handles for such file
		fileinfo := f.findFile(fileKey, fileObject)
		// try to resolve mapped file name if not found in internal state
		if fileinfo == nil && e.IsMapViewFile() {
			sec := e.Kparams.MustGetUint32(kparams.FileViewSectionType)
			isMapped := sec != va.SectionPagefile && sec != va.SectionPhysical
			if !isMapped {
				return e, nil
			}
			process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, e.PID)
			if err != nil {
				return e, nil
			}
			defer windows.Close(process)
			addr := e.Kparams.MustGetUint64(kparams.FileViewBase) + (e.Kparams.MustGetUint64(kparams.FileOffset))
			fileinfo = &FileInfo{Name: f.devMapper.Convert(sys.GetMappedFile(process, uintptr(addr)))}
			f.files[fileKey] = fileinfo
		}

		// ignore object misses that are produced by CloseFile
		if fileinfo == nil && e.IsCloseFile() {
			fileObjectMisses.Add(1)
		}
		if e.IsDeleteFile() {
			delete(f.files, fileObject)
		}
		if e.IsEnumDirectory() {
			if fileinfo != nil {
				e.AppendParam(kparams.FileDirectory, kparams.FilePath, fileinfo.Name)
			}
			return e, nil
		}
		if fileinfo != nil {
			if fileinfo.Type != fs.Unknown {
				e.AppendEnum(kparams.FileType, uint32(fileinfo.Type), fs.FileTypes)
			}
			e.AppendParam(kparams.FileName, kparams.FilePath, fileinfo.Name)
		}
	}
	return e, nil
}

func (f *fsProcessor) findFile(fileKey, fileObject uint64) *FileInfo {
	fileinfo, ok := f.files[fileKey]
	if ok {
		return fileinfo
	}
	fileinfo, ok = f.files[fileObject]
	if ok {
		return fileinfo
	}
	// look in the system handles for file objects
	var file htypes.Handle
	file, ok = f.hsnap.FindByObject(fileObject)
	if !ok {
		return nil
	}
	if file.Type == handle.File {
		fileObjectHandleHits.Add(1)
		return &FileInfo{Name: file.Name, Type: fs.GetFileType(file.Name, 0)}
	}
	return nil
}
