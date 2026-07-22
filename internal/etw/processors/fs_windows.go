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

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
)

var (
	// totalRundownFiles counts the number of opened files
	totalRundownFiles    = expvar.NewInt("fs.total.rundown.files")
	totalMapRundownFiles = expvar.NewInt("fs.total.map.rundown.files")
	// fileObjectMisses computes file object cache misses
	fileObjectMisses     = expvar.NewInt("fs.file.objects.misses")
	fileObjectHandleHits = expvar.NewInt("fs.file.object.handle.hits")
	fileReleaseCount     = expvar.NewInt("fs.file.releases")
)

type fsProcessor struct {
	// files stores the file metadata indexed by file object
	files map[uint64]*FileInfo

	hsnap handle.Snapshotter
	psnap ps.Snapshotter

	config *config.Config
}

// FileInfo stores file information obtained from event state.
type FileInfo struct {
	Name string
	Type fs.FileType
}

func newFsProcessor(
	hsnap handle.Snapshotter,
	psnap ps.Snapshotter,
	config *config.Config,
) Processor {
	return &fsProcessor{
		files:  make(map[uint64]*FileInfo),
		hsnap:  hsnap,
		psnap:  psnap,
		config: config,
	}
}

func (f *fsProcessor) ProcessEvent(e *event.Event) (*event.Event, bool, error) {
	if e.Category == event.File {
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

func (f *fsProcessor) processEvent(e *event.Event) (*event.Event, error) {
	switch e.Type {
	case event.FileRundown:
		// when the file rundown event comes in we store the file info
		// in internal state in order to augment the rest of file events
		// that lack the file path field
		filepath := e.GetParamAsString(params.FilePath)
		fileObject, err := e.Params.GetUint64(params.FileObject)
		if err != nil {
			return nil, err
		}
		if _, ok := f.files[fileObject]; !ok {
			totalRundownFiles.Add(1)
			f.files[fileObject] = &FileInfo{Name: filepath, Type: fs.GetFileType(filepath, 0)}
		}
	case event.MapFileRundown:
		fileKey := e.Params.MustGetUint64(params.FileKey)
		fileinfo := f.files[fileKey]

		if fileinfo != nil {
			totalMapRundownFiles.Add(1)
			e.AppendParam(params.FilePath, params.Path, fileinfo.Name)
		}

		return e, f.psnap.AddMmap(e)
	case event.CreateFile:
		fileObject := e.Params.MustGetUint64(params.FileObject)

		// try to get extended file info. If the file object is already
		// present in the map, we'll reuse the existing file information
		fileinfo, ok := f.files[fileObject]
		if !ok {
			opts := e.Params.MustGetUint32(params.FileCreateOptions)
			opts &= 0xFFFFFF
			filepath := e.GetParamAsString(params.FilePath)
			fileinfo = f.getFileInfo(filepath, opts)
			f.files[fileObject] = fileinfo
		}

		if fileinfo.Type != fs.Unknown {
			e.AppendEnum(params.FileType, uint32(fileinfo.Type), fs.FileTypes)
		}

		// invalidate signature cache / file metadata
		if e.IsOverwriteDisposition() {
			fs.GetMetadataStore().RemoveFile(e.GetParamAsString(params.FilePath))
			signature.GetSignatures().RemoveSignature(e.GetParamAsString(params.FilePath))
		}
		// start async file metadata resolution
		if e.IsCreateDisposition() && e.IsSuccess() {
			fs.GetMetadataStore().DoRequestAsync(e.GetParamAsString(params.FilePath))
		}

		return e, nil
	case event.ReleaseFile:
		fileReleaseCount.Add(1)
		// delete file metadata by file object address
		fileObject := e.Params.MustGetUint64(params.FileObject)
		delete(f.files, fileObject)
	case event.UnmapViewFile:
		ok, proc := f.psnap.Find(e.PID)
		addr := e.Params.TryGetAddress(params.FileViewBase)
		if ok {
			mmap := proc.FindMmap(addr)
			if mmap != nil {
				e.AppendParam(params.FilePath, params.Path, mmap.File)
			}
		}

		totalMapRundownFiles.Add(-1)

		return e, f.psnap.RemoveMmap(e.PID, addr)
	default:
		var fileObject uint64
		fileKey := e.Params.MustGetUint64(params.FileKey)

		if !e.IsMapViewFile() {
			fileObject = e.Params.MustGetUint64(params.FileObject)
		}

		// attempt to get the file by file key. If there is no such file referenced
		// by the file key, then try to fetch it by file object. Even if file object
		// references fails, we search in the file handles for such file
		fileinfo := f.findFile(fileKey, fileObject)

		// ignore object misses that are produced by CloseFile
		if fileinfo == nil && !e.IsCloseFile() {
			fileObjectMisses.Add(1)
		}

		if e.IsDeleteFile() {
			delete(f.files, fileObject)
			if fileinfo != nil {
				fs.GetMetadataStore().RemoveFile(fileinfo.Name)
				signature.GetSignatures().RemoveSignature(fileinfo.Name)
			}
		}
		if e.IsRenameFile() {
			if fileinfo != nil {
				fs.GetMetadataStore().RemoveFile(fileinfo.Name)
				signature.GetSignatures().RemoveSignature(fileinfo.Name)
			}
		}
		if e.IsEnumDirectory() {
			if fileinfo != nil {
				e.AppendParam(params.FileDirectory, params.Path, fileinfo.Name)
			}
			return e, nil
		}

		if fileinfo != nil {
			if fileinfo.Type != fs.Unknown {
				e.AppendEnum(params.FileType, uint32(fileinfo.Type), fs.FileTypes)
			}
			e.AppendParam(params.FilePath, params.Path, fileinfo.Name)
		}

		if e.IsMapViewFile() {
			return e, f.psnap.AddMmap(e)
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
