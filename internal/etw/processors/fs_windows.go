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
	"github.com/gammazero/deque"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"sync"
	"time"
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
	// mmaps stores memory-mapped files by pid and file object
	mmaps map[uint32]map[uint64]*MmapInfo

	hsnap handle.Snapshotter
	psnap ps.Snapshotter

	// irps contains a mapping between the IRP (I/O request packet) and CreateFile events
	irps map[uint64]*kevent.Kevent

	devMapper       fs.DevMapper
	devPathResolver fs.DevPathResolver
	config          *config.Config

	deq    *deque.Deque[*kevent.Kevent]
	mu     sync.Mutex
	purger *time.Ticker

	quit chan struct{}
}

// FileInfo stores file information obtained from event state.
type FileInfo struct {
	Name string
	Type fs.FileType
}

// MmapInfo stores information of the memory-mapped file.
type MmapInfo struct {
	File     string
	BaseAddr uint64
	Size     uint64
}

func newFsProcessor(
	hsnap handle.Snapshotter,
	psnap ps.Snapshotter,
	devMapper fs.DevMapper,
	devPathResolver fs.DevPathResolver,
	config *config.Config,
) Processor {
	f := &fsProcessor{
		files:           make(map[uint64]*FileInfo),
		mmaps:           make(map[uint32]map[uint64]*MmapInfo),
		irps:            make(map[uint64]*kevent.Kevent),
		hsnap:           hsnap,
		psnap:           psnap,
		devMapper:       devMapper,
		devPathResolver: devPathResolver,
		config:          config,
		deq:             deque.New[*kevent.Kevent](100),
		purger:          time.NewTicker(time.Second * 5),
		quit:            make(chan struct{}, 1),
	}

	go f.purge()

	return f
}

func (f *fsProcessor) ProcessEvent(e *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if e.Category == ktypes.File || e.IsStackWalk() {
		evt, err := f.processEvent(e)
		return evt, false, err
	}
	return e, true, nil
}

func (*fsProcessor) Name() ProcessorType { return Fs }
func (f *fsProcessor) Close()            { f.quit <- struct{}{} }

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
		// if the memory-mapped view refers to the image/data file
		// we store it in internal state for each process. The state
		// is consulted later when we process unmap events
		sec := e.Kparams.MustGetUint32(kparams.FileViewSectionType)
		isMapped := sec != va.SectionPagefile && sec != va.SectionPhysical
		if !isMapped {
			return e, nil
		}
		fileKey := e.Kparams.MustGetUint64(kparams.FileKey)
		viewBase := e.Kparams.MustGetUint64(kparams.FileViewBase)
		viewSize := e.Kparams.MustGetUint64(kparams.FileViewSize)
		f.initMmap(e.PID)
		fileinfo := f.files[fileKey]
		if fileinfo != nil {
			totalMapRundownFiles.Add(1)
			f.mmaps[e.PID][fileKey] = &MmapInfo{File: fileinfo.Name, BaseAddr: viewBase, Size: viewSize}
		} else {
			process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, e.PID)
			if err != nil {
				return e, nil
			}
			defer windows.Close(process)
			totalMapRundownFiles.Add(1)
			addr := e.Kparams.MustGetUint64(kparams.FileViewBase) + (e.Kparams.MustGetUint64(kparams.FileOffset))
			name := f.devMapper.Convert(sys.GetMappedFile(process, uintptr(addr)))
			f.mmaps[e.PID][fileKey] = &MmapInfo{File: name, BaseAddr: viewBase, Size: viewSize}
		}
		e.AppendParam(kparams.FileName, kparams.FilePath, f.mmaps[e.PID][fileKey].File)
		return e, f.psnap.AddFileMapping(e)
	case ktypes.CreateFile:
		// we defer the processing of the CreateFile event until we get
		// the matching FileOpEnd event. This event contains the operation
		// that was done on behalf of the file, e.g. create or open.
		irp := e.Kparams.MustGetUint64(kparams.FileIrpPtr)
		e.WaitEnqueue = true
		f.irps[irp] = e
	case ktypes.StackWalk:
		if !kevent.IsCurrentProcDropped(e.PID) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.deq.PushBack(e)
		}
	case ktypes.FileOpEnd:
		// get the CreateFile pending event by IRP identifier
		// and fetch the file create disposition value
		var (
			irp    = e.Kparams.MustGetUint64(kparams.FileIrpPtr)
			dispo  = e.Kparams.MustGetUint64(kparams.FileExtraInfo)
			status = e.Kparams.MustGetUint32(kparams.NTStatus)
		)
		if dispo > windows.FILE_MAXIMUM_DISPOSITION {
			return e, nil
		}
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
		if f.config.Kstream.EnableHandleKevents {
			f.devPathResolver.AddPath(ev.GetParamAsString(kparams.FileName))
		}
		ev.AppendParam(kparams.NTStatus, kparams.Status, status)
		if fileinfo.Type != fs.Unknown {
			ev.AppendEnum(kparams.FileType, uint32(fileinfo.Type), fs.FileTypes)
		}
		ev.AppendEnum(kparams.FileOperation, uint32(dispo), fs.FileCreateDispositions)

		// attach stack walk return addresses. CreateFile events
		// represent an edge case in callstack enrichment. Since
		// the events are delayed until the respective FileOpEnd
		// event arrives, we enable stack tracing for CreateFile
		// events. When the CreateFile event is generated, we store
		// it pending IRP map. Subsequently, the stack walk event is
		// generated which we put inside the queue. After FileOpEnd
		// arrives, the previous stack walk for CreateFile is popped
		// from the queue and the callstack parameter attached to the
		// event.
		if f.config.Kstream.StackEnrichment {
			f.mu.Lock()
			defer f.mu.Unlock()
			i := f.deq.RIndex(func(evt *kevent.Kevent) bool { return evt.StackID() == ev.StackID() })
			if i != -1 {
				s := f.deq.Remove(i)
				callstack := s.Kparams.MustGetSlice(kparams.Callstack)
				ev.AppendParam(kparams.Callstack, kparams.Slice, callstack)
			}
		}

		// parse PE data for created files and append parameters
		if ev.IsCreateDisposition() && ev.IsSuccess() {
			err := parseImageFileCharacteristics(ev)
			if err != nil {
				return ev, nil
			}
		}
		return ev, nil
	case ktypes.ReleaseFile:
		fileReleaseCount.Add(1)
		// delete both, the file object and the file key from files map
		fileKey := e.Kparams.MustGetUint64(kparams.FileKey)
		fileObject := e.Kparams.MustGetUint64(kparams.FileObject)
		delete(f.files, fileKey)
		delete(f.files, fileObject)
	case ktypes.UnmapViewFile:
		_ = f.psnap.RemoveFileMapping(e.PID, e.Kparams.TryGetAddress(kparams.FileViewBase))
		fileKey := e.Kparams.MustGetUint64(kparams.FileKey)
		if _, ok := f.mmaps[e.PID]; !ok {
			return e, nil
		}
		mmapinfo := f.mmaps[e.PID][fileKey]
		if mmapinfo != nil {
			e.AppendParam(kparams.FileName, kparams.FilePath, mmapinfo.File)
		}
		totalMapRundownFiles.Add(-1)
		delete(f.mmaps[e.PID], fileKey)
		if len(f.mmaps[e.PID]) == 0 {
			// process terminated, all files unmapped
			f.removeMmap(e.PID)
		}
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
			viewBase := e.Kparams.MustGetUint64(kparams.FileViewBase)
			viewSize := e.Kparams.MustGetUint64(kparams.FileViewSize)
			addr := e.Kparams.MustGetUint64(kparams.FileViewBase) + (e.Kparams.MustGetUint64(kparams.FileOffset))
			name := f.devMapper.Convert(sys.GetMappedFile(process, uintptr(addr)))
			f.initMmap(e.PID)
			f.mmaps[e.PID][fileKey] = &MmapInfo{File: name, BaseAddr: viewBase, Size: viewSize}
			e.AppendParam(kparams.FileName, kparams.FilePath, name)
			return e, f.psnap.AddFileMapping(e)
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
		if e.IsMapViewFile() {
			return e, f.psnap.AddFileMapping(e)
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

func (f *fsProcessor) initMmap(pid uint32) {
	m := f.mmaps[pid]
	if m == nil {
		f.mmaps[pid] = make(map[uint64]*MmapInfo)
	}
}

func (f *fsProcessor) removeMmap(pid uint32) {
	delete(f.mmaps, pid)
}

func (f *fsProcessor) purge() {
	for {
		select {
		case <-f.purger.C:
			f.mu.Lock()
			// evict unmatched stack traces
			for i := 0; i < f.deq.Len(); i++ {
				evt := f.deq.At(i)
				if time.Since(evt.Timestamp) > time.Second*30 {
					f.deq.Remove(i)
				}
			}
			f.mu.Unlock()
		case <-f.quit:
			return
		}
	}
}
