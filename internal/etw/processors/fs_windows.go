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
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"golang.org/x/time/rate"
)

var (
	// totalRundownFiles counts the number of opened files
	totalRundownFiles    = expvar.NewInt("fs.total.rundown.files")
	totalMapRundownFiles = expvar.NewInt("fs.total.map.rundown.files")
	// fileObjectMisses computes file object cache misses
	fileObjectMisses     = expvar.NewInt("fs.file.objects.misses")
	fileObjectHandleHits = expvar.NewInt("fs.file.object.handle.hits")
	fileReleaseCount     = expvar.NewInt("fs.file.releases")

	fsFileCharacteristicsRateLimits = expvar.NewInt("fs.file.characteristics.rate.limits")
)

type fsProcessor struct {
	// files stores the file metadata indexed by file object
	files map[uint64]*FileInfo

	hsnap handle.Snapshotter
	psnap ps.Snapshotter

	// irps contains a mapping between the IRP (I/O request packet) and CreateFile events
	irps map[uint64]*event.Event

	devMapper       fs.DevMapper
	devPathResolver fs.DevPathResolver
	config          *config.Config

	// buckets stores stack walk events per stack id
	buckets map[uint64][]*event.Event
	mu      sync.Mutex
	purger  *time.Ticker

	quit chan struct{}
	// lim throttles the parsing of image characteristics
	lim *rate.Limiter
}

// FileInfo stores file information obtained from event state.
type FileInfo struct {
	Name string
	Type fs.FileType
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
		irps:            make(map[uint64]*event.Event),
		hsnap:           hsnap,
		psnap:           psnap,
		devMapper:       devMapper,
		devPathResolver: devPathResolver,
		config:          config,
		buckets:         make(map[uint64][]*event.Event),
		purger:          time.NewTicker(time.Second * 5),
		quit:            make(chan struct{}, 1),
		lim:             rate.NewLimiter(30, 40), // allow 30 parse ops per second or bursts of 40 ops
	}

	go f.purge()

	return f
}

func (f *fsProcessor) ProcessEvent(e *event.Event) (*event.Event, bool, error) {
	if e.Category == event.File || e.IsStackWalk() {
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
		} else {
			// if the view of section is backed by the data/image file
			// try to get the mapped file name and append it to params
			sec := e.Params.MustGetUint32(params.FileViewSectionType)
			isMapped := sec != va.SectionPagefile && sec != va.SectionPhysical
			if isMapped {
				totalMapRundownFiles.Add(1)
				addr := e.Params.MustGetUint64(params.FileViewBase) + (e.Params.MustGetUint64(params.FileOffset))
				e.AppendParam(params.FilePath, params.Path, f.getMappedFile(e.PID, addr))
			}
		}

		return e, f.psnap.AddMmap(e)
	case event.CreateFile:
		// we defer the processing of the CreateFile event until we get
		// the matching FileOpEnd event. This event contains the operation
		// that was done on behalf of the file, e.g. create or open.
		irp := e.Params.MustGetUint64(params.FileIrpPtr)
		e.WaitEnqueue = true
		f.irps[irp] = e
	case event.StackWalk:
		if !event.IsCurrentProcDropped(e.PID) {
			f.mu.Lock()
			defer f.mu.Unlock()

			// append the event to the bucket indexed by stack id
			id := e.StackID()
			q, ok := f.buckets[id]
			if !ok {
				f.buckets[id] = []*event.Event{e}
			} else {
				f.buckets[id] = append(q, e)
			}
		}
	case event.FileOpEnd:
		// get the CreateFile pending event by IRP identifier
		// and fetch the file create disposition value
		var (
			irp    = e.Params.MustGetUint64(params.FileIrpPtr)
			dispo  = e.Params.MustGetUint64(params.FileExtraInfo)
			status = e.Params.MustGetUint32(params.NTStatus)
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
		fileObject := ev.Params.MustGetUint64(params.FileObject)

		// try to get extended file info. If the file object is already
		// present in the map, we'll reuse the existing file information
		fileinfo, ok := f.files[fileObject]
		if !ok {
			opts := ev.Params.MustGetUint32(params.FileCreateOptions)
			opts &= 0xFFFFFF
			filepath := ev.GetParamAsString(params.FilePath)
			fileinfo = f.getFileInfo(filepath, opts)
			f.files[fileObject] = fileinfo
		}

		if f.config.EventSource.EnableHandleEvents {
			f.devPathResolver.AddPath(ev.GetParamAsString(params.FilePath))
		}

		ev.AppendParam(params.NTStatus, params.Status, status)
		if fileinfo.Type != fs.Unknown {
			ev.AppendEnum(params.FileType, uint32(fileinfo.Type), fs.FileTypes)
		}
		ev.AppendEnum(params.FileOperation, uint32(dispo), fs.FileCreateDispositions)

		// attach stack walk return addresses. CreateFile events
		// represent an edge case in callstack enrichment. Since
		// the events are delayed until the respective FileOpEnd
		// event arrives, we enable stack tracing for CreateFile
		// events. When the CreateFile event is generated, we store
		// it in pending IRP map. Subsequently, the stack walk event
		// is put inside the queue. After FileOpEnd event arrives,
		// the previous stack walk for CreateFile is popped from
		// the queue and the callstack parameter attached to the
		// event.
		if f.config.EventSource.StackEnrichment {
			f.mu.Lock()
			defer f.mu.Unlock()

			id := ev.StackID()
			q, ok := f.buckets[id]
			if ok && len(q) > 0 {
				var s *event.Event
				s, f.buckets[id] = q[len(q)-1], q[:len(q)-1]
				callstack := s.Params.MustGetSlice(params.Callstack)
				ev.AppendParam(params.Callstack, params.Slice, callstack)
			}
		}

		// parse PE data for created files and append parameters
		if ev.IsCreateDisposition() && ev.IsSuccess() {
			if !f.lim.Allow() {
				fsFileCharacteristicsRateLimits.Add(1)
				return ev, nil
			}
			path := ev.GetParamAsString(params.FilePath)
			c, err := parseImageFileCharacteristics(path)
			if err != nil {
				return ev, nil
			}
			ev.AppendParam(params.FileIsDLL, params.Bool, c.isDLL)
			ev.AppendParam(params.FileIsDriver, params.Bool, c.isDriver)
			ev.AppendParam(params.FileIsExecutable, params.Bool, c.isExe)
			ev.AppendParam(params.FileIsDotnet, params.Bool, c.isDotnet)
		}

		return ev, nil
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

		// try to resolve mapped file name if not found in internal state
		if fileinfo == nil && e.IsMapViewFile() {
			sec := e.Params.MustGetUint32(params.FileViewSectionType)
			isMapped := sec != va.SectionPagefile && sec != va.SectionPhysical
			if isMapped {
				totalMapRundownFiles.Add(1)
				addr := e.Params.MustGetUint64(params.FileViewBase) + (e.Params.MustGetUint64(params.FileOffset))
				e.AppendParam(params.FilePath, params.Path, f.getMappedFile(e.PID, addr))
			}
		}

		// ignore object misses that are produced by CloseFile
		if fileinfo == nil && !e.IsCloseFile() {
			fileObjectMisses.Add(1)
		}

		if e.IsDeleteFile() {
			delete(f.files, fileObject)
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

func (f *fsProcessor) getMappedFile(pid uint32, addr uint64) string {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.Close(process)
	return f.devMapper.Convert(sys.GetMappedFile(process, uintptr(addr)))
}

func (f *fsProcessor) purge() {
	for {
		select {
		case <-f.purger.C:
			f.mu.Lock()

			// evict unmatched stack traces
			for id, q := range f.buckets {
				s := q[:0]
				for _, evt := range q {
					if time.Since(evt.Timestamp) <= time.Second*30 {
						s = append(s, evt)
					}
				}
				f.buckets[id] = s
			}

			f.mu.Unlock()
		case <-f.quit:
			return
		}
	}
}
