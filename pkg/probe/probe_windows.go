/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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

package probe

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/expirable"
	libetw "github.com/rabbitstack/fibratus/internal/etw"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/pipeline"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/cmdline"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/rabbitstack/fibratus/pkg/util/pair"
	"github.com/rabbitstack/fibratus/pkg/util/periodical"
	"github.com/rabbitstack/fibratus/pkg/util/ports"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/rabbitstack/fibratus/pkg/util/stringcache"
	"github.com/rabbitstack/fibratus/pkg/util/utf16"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"

	log "github.com/sirupsen/logrus"
)

const maxEnqueuedIORequests = 200

const ringSize = 1 << 16

// maxPendingIOWait is how long a CreateFile may wait for its FileOpEnd before
// it is considered lost and evicted. Normal completions take microseconds, so
// this is deliberately generous.
var maxPendingIOWait = 5 * time.Second

// ioSweepInterval throttles the stale-request sweep.
const ioSweepInterval = time.Second

type Probe struct {
	PlatformProbe

	kernelTrace *libetw.KernelTrace
	userTrace   *libetw.UserTrace

	filePathResolver map[uint64]FileInfo              // maps file object pointer to file info
	fcbPathResolver  *expirable.LRU[uint64, FileInfo] // maps FCB (File Control Block) pointer to file info

	kcbPathResolver map[uint64]string // maps KCB (Key Control Block) pointer to registry path

	filePathStringCache *stringcache.StringCache
	kcbPathStringCache  *stringcache.ScopedStringCache

	// stores pending I/O request packets
	enqueuedIORequests map[uint64]ioRequest

	// enqueuedRegSetValues keeps temporarily RegSetValue internal events by pid and base value name
	enqueuedRegSetValues *expirable.LRU[pair.Pair[uint32, string], *event.Event]

	config *config.Config

	psnap ps.Snapshotter

	wg         sync.WaitGroup
	ctx        context.Context
	cancelFunc context.CancelFunc

	errs chan error

	rs *config.RulesCompileResult

	pipeline *pipeline.Pipeline

	linker *CallstackLinker

	// periodics keeps a list of periodical runners per pipeline producer ID.
	periodics [pipeline.ProducerMax + 1][]periodical.Periodic

	regionProber *va.RegionProber
}

// ioRequest acts as a scratch area for the pending IRP request
// that is used as a signal to promote the file operation.
// The memory buffer backing the event record is valid until
// the callback returns. Any state that needs to outlive the
// buffer lifetime must copy it safely.
type ioRequest struct {
	rec   *etw.EventRecord // keeps the original CreateFile event record
	buf   []byte           // keeps the data buffer alive
	stack va.Callstack     // claimed CreateFile call stack addresses
}

func (p *Probe) Init(rs *config.RulesCompileResult) error {
	var enableDNS bool
	var enableRegistry bool
	var enableAuditAPI bool
	p.rs = rs

	if rs != nil {
		// Configure drop types if the rule engine is enabled, which is
		// the default for sensor mode. For any event not present in the
		// rule set, the bitmap rejects it is offloaded from the session
		// buffers
		p.config.EventSource.AddDropTypes(slices.DeleteFunc(slices.Clone(event.AllTypes()), func(t event.Type) bool {
			if t.OnlyState() || t.StateSnapshot() {
				// State events are always accepted
				return true
			}

			if t == event.CreateProcess || t == event.TerminateProcess || t == event.CreateThread ||
				t == event.LoadModule || t == event.UnloadModule || t == event.TerminateThread {
				// Fundamental events are always accepted
				return true
			}

			if p.config.Yara.Enabled {
				// Allow events required for memory/file scanning
				switch {
				case t == event.MapViewOfSection && !p.config.Yara.SkipMmaps:
					return true
				case t == event.VirtualAlloc && !p.config.Yara.SkipAllocs:
					return true
				case t == event.CreateFile && !p.config.Yara.SkipFiles:
					return true
				case t == event.RegSetValue && !p.config.Yara.SkipRegistry:
					return true
				}
			}

			return rs.ContainsEvent(t)
		})...)

		p.kernelTrace.SetKernelEventFlags(p.toKernelEventFlags(rs))

		enableDNS = rs.HasDNSEvents
		enableRegistry = rs.HasRegistryEvents
		enableAuditAPI = rs.HasAuditAPIEvents
	} else {
		enableDNS = p.config.EventSource.EnableDNSEvents
		enableRegistry = p.config.EventSource.EnableRegistryEvents
		enableAuditAPI = p.config.EventSource.EnableAuditAPIEvents
	}

	// Windows Kernel Process session permits enriching event state with
	// additional attributes and guaranteeing that any event published by
	// the security telemetry session doesn't miss its respective process
	// from the snapshotter
	p.userTrace.AddProvider(etw.WindowsKernelProcessGUID, libetw.WithKeywords(etw.ProcessKeyword|etw.ImageKeyword), libetw.WithCaptureState())

	// In a similar vein, Windows Kernel Registry provider publishes
	// the RegSetValue event with the full captured data for the
	// modified value. This data is used to attach various parameters
	// to the RegSetValue event published by the NT Kernel Logger
	if enableRegistry {
		p.userTrace.AddProvider(etw.WindowsKernelRegistryGUID, libetw.WithKeywords(etw.SetValueKeyword), libetw.WithEventFilterDescriptors(etw.EventFilterDescriptor{
			Ptr:  uintptr(unsafe.Pointer(&etw.CaptureRegistryValue)),
			Size: 4,
		}))
	}

	if enableDNS {
		p.userTrace.AddProvider(etw.DNSClientGUID)
	}

	if enableAuditAPI {
		p.userTrace.AddProvider(etw.KernelAuditAPICallsGUID, libetw.WithCallstack(p.config.EventSource.StackEnrichment))
	}

	return nil
}

func (p *Probe) toKernelEventFlags(rs *config.RulesCompileResult) etw.EventTraceFlags {
	eventFlags := etw.Process | etw.Module | etw.Thread

	if rs.HasNetworkEvents {
		eventFlags |= etw.NetTCPIP
	}
	if rs.HasFileEvents || (p.config.Yara.Enabled && !p.config.Yara.SkipFiles) {
		eventFlags |= etw.DiskFileIO | etw.FileIO | etw.FileIOInit
	}
	if rs.HasVAMapEvents || (p.config.Yara.Enabled && !p.config.Yara.SkipMmaps) {
		eventFlags |= etw.VaMap
	}
	if rs.HasMemEvents || (p.config.Yara.Enabled && !p.config.Yara.SkipAllocs) {
		eventFlags |= etw.VirtualAlloc
	}
	if rs.HasRegistryEvents || (p.config.Yara.Enabled && !p.config.Yara.SkipRegistry) {
		eventFlags |= etw.Registry
	}

	return eventFlags
}

func (p *Probe) Start() error {
	if err := p.userTrace.Start(); err != nil {
		return err
	}
	if err := p.kernelTrace.Start(); err != nil {
		return err
	}

	if err := p.userTrace.Open(); err != nil {
		return err
	}
	if err := p.userTrace.CaptureState(); err != nil {
		log.Warnf("unable to capture trace %s state: %v", p.userTrace.Name(), err)
	}

	if err := p.kernelTrace.Open(); err != nil {
		return err
	}

	handlePanic := func() {
		if r := recover(); r != nil {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			log.Fatalf("panic in trace processing goroutine: %v\n%s", r, buf[:n])
		}
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer handlePanic()
		p.userTrace.Process(func(rec *etw.EventRecord) error {
			return p.processEvent(pipeline.ProducerUser, rec)
		}, p.errs)
	}()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer handlePanic()
		p.kernelTrace.Process(func(rec *etw.EventRecord) error {
			return p.processEvent(pipeline.ProducerKernel, rec)
		}, p.errs)
	}()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			select {
			case <-p.ctx.Done():
				return
			case err := <-p.errs:
				if err != nil && !errors.Is(err, filter.ErrEventFilteredOut) {
					log.Errorf("probe runtime error: %v", err)
				}
			}
		}
	}()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.pipeline.Start()
	}()

	for _, pc := range p.consumers {
		pc.Start(p.ctx, &p.wg)
	}

	return nil
}

func (p *Probe) Close() error {
	var errs []error

	// Flush and stop the user trace
	if err := p.userTrace.Flush(); err != nil {
		errs = append(errs, err)
	}
	time.Sleep(time.Millisecond * 100)
	if err := p.userTrace.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := p.userTrace.Stop(); err != nil {
		errs = append(errs, err)
	}

	// Flush and stop the kernel trace
	if err := p.kernelTrace.Flush(); err != nil {
		errs = append(errs, err)
	}
	time.Sleep(time.Millisecond * 100)
	if err := p.kernelTrace.Close(); err != nil {
		errs = append(errs, err)
	}
	if err := p.kernelTrace.Stop(); err != nil {
		errs = append(errs, err)
	}

	p.pipeline.Close()

	p.cancelFunc()
	p.wg.Wait()

	return multierror.Wrap(errs...)
}

// processEvent is the entry point for every ETW event record delivered by the
// producer. Depending on the event type, the record is either committed to the
// ring buffer, parked until a related event arrives, used for state management
// or discarded.
func (p *Probe) processEvent(producerID pipeline.ProducerID, rec *etw.EventRecord) error {
	t := event.TypeFromEventRecord(rec)

	if event.IsCurrentProcDropped(rec) {
		return nil
	}

	if p.config.EventSource.HasDropType(t) {
		return nil
	}

	switch t {
	case event.CreateFile:
		return p.initIORequest(rec)
	case event.CloseFile:
		object := rec.ReadUint64(8)
		delete(p.filePathResolver, object)
		return nil
	case event.FileRundown:
		totalRundownFiles.Add(1)
		object := rec.ReadUint64(0)
		path := fs.GetDevMapper().Convert(rec.ConsumeUTF16String(8))
		p.filePathResolver[object] = FileInfo{Path: path, Type: fs.GetFileType(path, 0)}
		return nil
	case event.StackWalk:
		// CreateFile is held aside until FileOpEnd, so its callstack is parked on
		// the pending request instead of becoming a pipeline event per CreateFile.
		// The pending requests are only touched by the kernel trace goroutine.
		if producerID == pipeline.ProducerKernel && p.claimIORequestStack(rec) {
			return nil
		}
		return p.pipeline.Publish(producerID, t, func(evt *event.Event) { evt.Parse(rec) })
	case event.RegKCBRundown, event.RegCreateKCB:
		kcb := rec.ReadUint64(16)
		path := rec.ConsumeUTF16String(24)
		p.kcbPathResolver[kcb] = path
		return nil
	case event.RegDeleteKCB:
		kcb := rec.ReadUint64(16)
		delete(p.kcbPathResolver, kcb)
		return nil
	case event.Unknown:
		return nil
	}

	switch t {
	case event.FileOpEnd:
		return p.completeIORequest(producerID, rec)
	case event.MapViewOfSection, event.UnmapViewOfSection, event.MapViewSectionRundown, event.DeleteFile, event.SetFileInformation, event.RenameFile, event.EnumDirectory, event.ReadFile, event.WriteFile:
		return p.pipeline.Publish(producerID, t, func(evt *event.Event) {
			evt.Parse(rec)
			p.addFileInfoFromFCB(rec, evt)
		})
	case event.RegOpenKey, event.RegCreateKey, event.RegDeleteKey, event.RegQueryKey, event.RegQueryValue, event.RegSetValue, event.RegDeleteValue:
		path := p.resolveKCBPath(rec)
		if path == "" {
			path = rec.ConsumeUTF16String(24)
		}

		rootkey, subkey := key.Format(path)
		if rootkey != key.Invalid {
			root := rootkey.String()
			if subkey != "" {
				path = root + `\` + subkey
			} else {
				path = root
			}
		}

		if (t == event.RegOpenKey || t == event.RegQueryKey || t == event.RegQueryValue) &&
			!p.isRegPathApproved(path) {
			registryApproverRejections.Add(1)
			return nil
		}

		registryApproverApprovals.Add(1)

		return p.pipeline.Publish(producerID, t, func(evt *event.Event) {
			evt.Parse(rec)
			_ = evt.Params.SetValue(params.RegPath, path)
		})
	case event.OpenProcess, event.OpenThread:
		pid := rec.ReadUint32(0)
		if !p.isExecutablePathApproved(pid, t == event.OpenThread && rec.Header.ProcessID != pid) {
			procApproverRejections.Add(1)
			return nil
		}
		procApproverApprovals.Add(1)
	}

	producer := p.pipeline.Producer(producerID)
	evt := producer.Acquire(t)
	if evt == nil {
		return pipeline.ErrRingNoSlots
	}
	evt.Parse(rec)
	timestamp := evt.Timestamp.UnixNano()

	producer.Publish()

	// Run periodical tasks driven by monotonic event-time clock
	for _, periodic := range p.periodics[producerID] {
		periodic.RunPeriodic(timestamp)
	}

	return nil
}

// initIORequest clones the CreateFile record and keeps it in the
// pending I/O requests map until the matching FileOpEnd event arrives.
func (p *Probe) initIORequest(rec *etw.EventRecord) error {
	if len(p.enqueuedIORequests) > maxEnqueuedIORequests {
		return nil
	}
	clone, buf := rec.Clone()
	irp := rec.ReadUint64(0)
	p.enqueuedIORequests[irp] = ioRequest{rec: clone, buf: buf}
	return nil
}

// completeIORequest completes the pending CreateFile request identified
// by the IRP address and commits the resulting event to the ring buffer.
func (p *Probe) completeIORequest(producerID pipeline.ProducerID, rec *etw.EventRecord) error {
	var (
		disposition     uint32
		status          uint32
		isReparse       bool
		isRemount       bool
		isReparseGlobal bool
		reparseTag      uint32
	)

	// Dequeue the pending I/O packet
	irp := rec.ReadUint64(0)
	req, enqueued := p.enqueuedIORequests[irp]
	if !enqueued || req.rec.Header.Timestamp > rec.Header.Timestamp {
		return nil
	}
	defer req.rec.ReleasePool()
	delete(p.enqueuedIORequests, irp)

	// Drive the state management of active files
	object := req.rec.ReadUint64(8)
	opts := req.rec.ReadUint32(20)

	pathUTF16 := req.rec.ConsumeRawUTF16String(32)
	path, ok := p.filePathStringCache.Lookup(pathUTF16)
	if !ok {
		n := utf16.Decode(pathUTF16)
		path = fs.GetDevMapper().Convert(n)
		p.filePathStringCache.Add(pathUTF16, path)
	}

	status = rec.ReadUint32(16)
	ioStatus := uint32(rec.ReadUint64(8))
	if windows.NTStatus(status) == windows.STATUS_REPARSE {
		// Inherit caller's create disposition
		disposition = opts >> 24
		switch ioStatus {
		case sys.IoReparse:
			isReparse = true
		case sys.IoRemount:
			isRemount = true
		case sys.IoReparseGlobal:
			isReparseGlobal = true
		default:
			reparseTag = ioStatus
		}
	} else {
		disposition = ioStatus
	}

	f := FileInfo{
		Path:            path,
		Type:            fs.GetFileType(path, opts&0xFFFFFF),
		IsReparse:       isReparse,
		IsRemount:       isRemount,
		IsReparseGlobal: isReparseGlobal,
		ReparseTag:      reparseTag,
	}
	p.filePathResolver[object] = f

	if !p.isFileApproved(path, disposition) {
		fsApproverRejections.Add(1)
		if req.stack != nil {
			req.stack.ReleasePool()
		}
		return nil
	}

	fsApproverApprovals.Add(1)

	return p.pipeline.Publish(producerID, event.CreateFile, func(evt *event.Event) {
		evt.Parse(req.rec)
		// Attach create disposition and NT status parameters
		evt.AppendParam(params.NTStatus, params.Status, status)
		evt.AppendEnum(params.FileOperation, disposition, fs.FileCreateDispositions)
		// The callstack arrived while the request was pending. The event now
		// owns the return addresses and skips the linker
		if req.stack != nil {
			evt.AppendParam(params.Callstack, params.Slice, req.stack)
		}
	})
}

// claimIORequestStack parks the callstack carried by a StackWalk record on the
// pending CreateFile request it belongs to. It reports whether such a request
// exists. The stack walk is matched on the time stamp and the thread, because
// the time stamp alone isn't unique.
func (p *Probe) claimIORequestStack(rec *etw.EventRecord) bool {
	var ts = rec.ReadUint64(0)
	for irp, req := range p.enqueuedIORequests {
		if req.rec == nil || req.rec.Header.Timestamp != ts {
			continue
		}
		// a repeated stack walk replaces the previous one
		req.stack = rec.ReadCallstackInto(16, va.GetCallstackFromPool())
		p.enqueuedIORequests[irp] = req
		return true
	}
	return false
}

func (p *Probe) addFileInfoFromFCB(rec *etw.EventRecord, evt *event.Event) {
	fileinfo, found := p.resolveFileInfo(rec)
	if !found {
		fileObjectMisses.Add(1)
		return
	}
	path := fileinfo.Path
	if evt.IsEnumDirectory() {
		path = filepath.Join(path, evt.GetParamAsString(params.FilePath))
	}
	evt.AppendParam(params.FilePath, params.Path, path)
	evt.AppendEnum(params.FileType, uint32(fileinfo.Type), fs.FileTypes)
}

// linkCallstack hands the callstack carried by a StackWalk event over to the
// linker, which connects it with the event that triggered it. The stack walk
// itself is never dispatched. The linker owns the return addresses from now on,
// because the pipeline recycles the event once the handler returns.
func (p *Probe) linkCallstack(ew *event.Event) error {
	if p.linker == nil {
		return nil
	}
	param, err := ew.Params.Get(params.Callstack)
	if err != nil {
		return nil
	}
	addrs, ok := param.Value.(va.Callstack)
	if !ok {
		return nil
	}
	ts := ew.Params.MustGetUint64(params.CallstackTimestamp)
	tid := ew.Params.MustGetTid()
	p.linker.Link(ts, 0, tid, addrs)
	return nil
}

// resolveFileInfo tries FileObject first as authoritative, always populated on Create/
// Rundown and then falls back to file key works even if you missed the Create, as long
// as some later op event backfilled it.
func (p *Probe) resolveFileInfo(rec *etw.EventRecord) (FileInfo, bool) {
	var key uint64
	var object uint64

	switch rec.Header.EventDescriptor.Opcode {
	case event.MapViewOfSectionID, event.UnmapViewOfSectionID, event.MapViewSectionRundownID:
		key = rec.ReadUint64(8)
	case event.ReadFileID, event.WriteFileID:
		object = rec.ReadUint64(16)
		key = rec.ReadUint64(24)
	default:
		object = rec.ReadUint64(8)
		key = rec.ReadUint64(16)
	}

	file, found := p.filePathResolver[object]
	if found {
		// Backfill the FCB map opportunistically. File key never appears
		// on Create/Rundown but only on op events, so this is the only place
		// it can be populated. Only write once so we don't keep overwriting
		// with possibly reused later resolutions
		if rec.Header.EventDescriptor.Opcode == event.RenameFileID || p.fcbPathResolver.Contains(key) {
			p.fcbPathResolver.Remove(key)
			if key != 0 {
				p.fcbPathResolver.Add(key, file)
			}
		} else if key != 0 && !p.fcbPathResolver.Contains(key) {
			p.fcbPathResolver.Add(key, file)
		}
	}
	if !found {
		return p.fcbPathResolver.Get(key)
	}
	return file, found
}

// resolveKCBPath obeys a straightforward algorithm to connect relative
// key names to their root keys. If the KCB is equal to zero we have a
// full key name and don't have to go further resolving the missing part.
// Otherwise, we have to lookup existing KCBs to try find the matching base
// key name and concatenate its relative path.
func (p *Probe) resolveKCBPath(rec *etw.EventRecord) string {
	kcb := rec.ReadUint64(16)
	if kcb == 0 {
		return ""
	}

	if base, exists := p.kcbPathResolver[kcb]; exists {
		path := rec.ConsumeUTF16String(24)
		return base + `\` + path
	}

	return ""
}

func (p *Probe) handleEvent(evt *event.Event) error {
	var pid uint32
	switch evt.Type {
	case event.CreateFile:
		p.handleCreateFile(evt)
	case event.DeleteFile, event.RenameFile:
		p.handleModifyFile(evt)
	case event.StackWalk:
		return p.linkCallstack(evt)
	case event.MapViewSectionRundown, event.MapViewOfSection:
		if err := p.addMmap(evt); err != nil {
			return err
		}
	case event.UnmapViewOfSection:
		if err := p.removeMmap(evt); err != nil {
			return err
		}
	case event.CreateProcess, event.CreateProcessInternal, event.ProcessRundown, event.ProcessRundownInternal:
		if err := p.addProcess(evt); err != nil {
			return err
		}
	case event.TerminateProcess:
		if err := p.removeProcess(evt); err != nil {
			return err
		}
	case event.CreateThread, event.ThreadRundown:
		pid = evt.Params.MustGetPid()
		if err := p.addThread(evt); err != nil {
			return err
		}
	case event.TerminateThread:
		pid = evt.Params.MustGetPid()
		if err := p.removeThread(evt); err != nil {
			return err
		}
	case event.OpenProcess, event.OpenThread:
		pid = evt.Params.MustGetPid()
	case event.LoadModule, event.ModuleRundown, event.LoadModuleInternal:
		if err := p.addModule(evt); err != nil {
			return err
		}
	case event.UnloadModule:
		if err := p.removeModule(evt); err != nil {
			return err
		}
	case event.RegSetValue, event.RegSetValueInternal:
		p.handleRegSetValue(evt)
	case event.VirtualAlloc:
		p.handleVirtualAlloc(evt)
		pid = evt.Params.MustGetPid()
	case event.VirtualFree:
		pid = evt.Params.MustGetPid()
	case event.Accept, event.Connect, event.Send, event.Recv, event.Reconnect, event.Disconnect, event.Retransmit:
		p.resolvePortName(evt)
	}

	// Associate process' state with the event.
	// We only override the process' state if it hasn't
	// been set previously such as in the situation where
	// captures are being taken. Events that construct
	// the process' snapshot also have attached process
	// state, so simply by replaying the flow of these
	// events we are able to reconstruct system-wide
	// process state.
	exists, proc := p.psnap.Find(evt.PID)
	if !exists {
		p.psnap.Put(proc)
	}
	if evt.PS == nil {
		evt.PS = proc
	}

	if p.config.EventSource.HasDropProcess(proc) {
		return nil
	}

	if pid != 0 {
		if proc := p.psnap.FindAndPut(pid); proc != nil {
			evt.AppendParam(params.Exe, params.Path, proc.Exe)
			evt.AppendParam(params.ProcessName, params.AnsiString, proc.Name)
		}
	}

	if p.linker != nil {
		p.linker.doPeriodic(evt.Timestamp.UnixNano())
	}

	if p.config.EventSource.StackEnrichment && evt.Type.WaitStack() && !evt.Params.Contains(params.Callstack) {
		if paired := p.linker.Put(evt); paired != nil {
			return p.dispatchEvent(paired)
		}
		// The linker dispatches it when its stack walk arrives
		// or without the callstack when the wait interval expires
		return nil
	}

	return p.dispatchEvent(evt)
}

func (p *Probe) dispatchEvent(evt *event.Event) error {
	if err := p.sendEventToHandlers(evt); err != nil {
		return err
	}

	if err := p.sendEventToConsumers(evt); err != nil {
		return err
	}

	return nil
}

func (p *Probe) addProcess(evt *event.Event) error {
	if evt.IsCreateProcessInternal() || evt.IsProcessRundownInternal() {
		return nil
	}

	cmndline := cmdline.New(evt.GetParamAsString(params.Cmdline)).
		// get rid of leading/trailing quotes in the executable path
		CleanExe().
		// expand all variations of the SystemRoot environment variable
		ExpandSystemRoot().
		// some system processes are reported without the path in the command line,
		// but we can expand the path from the SystemRoot environment variable
		CompleteSysProc(evt.GetParamAsString(params.ProcessName))

	// append executable path parameter
	exe := cmndline.Exeline()
	if exe == "" {
		exe = evt.GetParamAsString(params.ProcessName)
	}
	evt.AppendParam(params.Exe, params.Path, exe)

	evt.AppendParam(params.StartTime, params.Time, evt.Timestamp)

	return p.psnap.Write(evt)
}

func (p *Probe) removeProcess(evt *event.Event) error {
	p.regionProber.Remove(evt.Params.MustGetPid())
	if err := p.psnap.Remove(evt); err != nil {
		return err
	}
	return nil
}

func (p *Probe) addThread(evt *event.Event) error {
	return p.psnap.AddThread(evt)
}

func (p *Probe) removeThread(evt *event.Event) error {
	pid := evt.Params.MustGetPid()
	tid := evt.Params.MustGetTid()
	return p.psnap.RemoveThread(pid, tid)
}

func (p *Probe) addModule(evt *event.Event) error {
	if evt.IsLoadModuleInternal() {
		return p.psnap.AddModule(evt)
	}

	// typ := signature.Type(evt.Params.MustGetUint32(params.ModuleSignatureType))
	// lvl := signature.Level(evt.Params.MustGetUint32(params.ModuleSignatureLevel))

	// // Code Integrity successfully validated the file's trust chain.
	// // The signature level WINDOWS and WINDOWS_TCB describes the trust
	// // level assigned after verification.
	// // A file can reach the WINDOWS signing level through either an embedded PE
	// // Authenticode signature or a catalog signature where the file hash lives
	// // in a trusted .cat file.
	// // Trusted signatures are automatically pushed to the store. On the contrary,
	// // signature verification is delegated to the async workers
	// key := evt.SignatureKey()
	// if signature.IsTrusted(typ, lvl) {
	// 	signature.GetSignatures().PutSignature(key, typ, lvl)
	// } else {
	// 	signature.GetSignatures().DoRequestAsync(key)
	// }

	// // request module file metadata by queueing async work
	// fs.GetMetadataStore().DoRequestAsync(evt.GetParamAsString(params.ModulePath), evt.IsModuleRundown())

	return p.psnap.AddModule(evt)
}

func (p *Probe) removeModule(evt *event.Event) error {
	pid := evt.Params.MustGetPid()
	addr := evt.Params.TryGetAddress(params.ModuleBase)
	if pid == 0 {
		pid = evt.PID
	}
	return p.psnap.RemoveModule(pid, addr)
}

func (p *Probe) addMmap(evt *event.Event) error {
	totalMapRundownFiles.Add(1)
	return p.psnap.AddMmap(evt)
}

func (p *Probe) removeMmap(evt *event.Event) error {
	totalMapRundownFiles.Add(-1)
	addr := evt.Params.TryGetAddress(params.FileViewBase)
	return p.psnap.RemoveMmap(evt.PID, addr)
}

func (p *Probe) handleCreateFile(evt *event.Event) {
	// Invalidate signature cache / file metadata
	if evt.IsOverwriteDisposition() {
		fs.GetMetadataStore().RemoveFile(evt.GetParamAsString(params.FilePath))
		signature.GetSignatures().RemoveSignature(evt.GetParamAsString(params.FilePath))
	}
	// Start async file metadata resolution
	if evt.IsCreateDisposition() && evt.IsSuccess() {
		fs.GetMetadataStore().DoRequestAsync(evt.GetParamAsString(params.FilePath), false)
	}
}

func (p *Probe) handleModifyFile(evt *event.Event) {
	path := evt.GetParamAsString(params.FilePath)
	if path != "" {
		fs.GetMetadataStore().RemoveFile(path)
		signature.GetSignatures().RemoveSignature(path)
	}
}

func (p *Probe) handleRegSetValue(evt *event.Event) {
	if evt.IsRegSetValueInternal() {
		// Park the internal RegSetValue event until the public
		// RegSetValue event for the same pid/value shows up
		path := evt.Params.MustGetString(params.RegPath)
		k := pair.New(evt.PID, filepath.Base(path))
		p.enqueuedRegSetValues.Add(k, evt.Clone())
		return
	}

	// Returns and removes the parked internal event
	// matching e, or nil if there is none to grab.
	// Previously stored RegSetValueInternal event
	// is popped from the queue. RegSetValue can
	// be enriched with registry value type/data
	k := pair.New(evt.PID, filepath.Base(evt.GetParamAsString(params.RegPath)))
	e, ok := p.enqueuedRegSetValues.Peek(k)
	if !ok {
		// Try to read captured data from userspace
		populateRegistryData(evt)
		return
	}
	p.enqueuedRegSetValues.Remove(k)

	// Enrich the event with value data/type parameters
	valueType, err := e.Params.GetUint32(params.RegValueType)
	if err == nil {
		evt.AppendEnum(params.RegValueType, valueType, key.RegistryValueTypes)
	}

	valueData, err := e.Params.Get(params.RegData)
	if err == nil {
		evt.AppendParam(params.RegData, valueData.Type, valueData.Value)
	}
}

func (p *Probe) handleVirtualAlloc(evt *event.Event) {
	// retrieve info about the range of pages and enrich the event
	// with allocation protection options and the type of pages in
	// the allocated region. If the region is mapped, we try to find
	// the backing file name
	addr := evt.Params.MustGetUint64(params.MemBaseAddress)
	region := p.regionProber.Query(evt.Params.MustGetPid(), addr)
	if region != nil {
		if region.IsMapped() {
			evt.AppendParam(params.FilePath, params.DOSPath, region.GetMappedFile())
		}
		evt.AppendEnum(params.MemPageType, region.Type, event.MemPageTypes)
		evt.AppendFlags(params.MemProtect, region.Protect, event.MemProtectionFlags)
		evt.AppendParam(params.MemProtectMask, params.AnsiString, region.ProtectMask())
	}
}

// resolvePortName resolves the IANA service name for the particular port and transport protocol as
// per https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml.
func (*Probe) resolvePortName(evt *event.Event) {
	dport := evt.Params.TryGetUint16(params.NetDport)
	sport := evt.Params.TryGetUint16(params.NetSport)

	if evt.IsNetworkTCP() {
		if name, ok := ports.TCPPortNames[dport]; ok {
			evt.Params.Append(params.NetDportName, params.AnsiString, name)
		}
		if name, ok := ports.TCPPortNames[sport]; ok {
			evt.Params.Append(params.NetSportName, params.AnsiString, name)
		}
		return
	}

	if name, ok := ports.UDPPortNames[dport]; ok {
		evt.Params.Append(params.NetDportName, params.AnsiString, name)
	}
	if name, ok := ports.UDPPortNames[sport]; ok {
		evt.Params.Append(params.NetSportName, params.AnsiString, name)
	}
}

func (p *Probe) Handle(evt *event.Event) {
	if err := p.handleEvent(evt); err != nil {
		select {
		case p.errs <- err:
		default:
		}
	}
}

// AddPeriodic adds a new periodic to the given producer slot. Beware periodics run in the
// event processing thread. For this reason, never run CPU-intensive tasks inside the periodic.
func (p *Probe) AddPeriodic(producerID pipeline.ProducerID, periodic periodical.Periodic) error {
	if producerID >= pipeline.ProducerMax {
		return fmt.Errorf("producer ID (%d) not allowed", producerID)
	}

	p.periodics[producerID] = append(p.periodics[producerID], periodic)

	return nil
}

// classifyEvent assigns the shedding priority of an event type. Events that
// build or tear down state (process, thread, module, the rundowns that seed
// them, and the internal RegSetValue that enriches the public one) must never
// be shed, or the process snapshot drifts and every later lookup misses.
// Everything else is ClassNormal. Once their volume is measured, move the
// high-volume types (file, registry, network) to pipeline.ClassNoisy so they
// are the first to go under pressure.
func classifyEvent(t event.Type) pipeline.ShedClass {
	switch t {
	case event.CreateProcess, event.CreateProcessInternal, event.ProcessRundown, event.ProcessRundownInternal,
		event.TerminateProcess, event.CreateThread, event.ThreadRundown, event.TerminateThread,
		event.LoadModule, event.ModuleRundown, event.LoadModuleInternal, event.UnloadModule,
		event.RegSetValueInternal, event.StackWalk:
		return pipeline.ClassState
	case event.CreateFile, event.RegOpenKey, event.RegQueryKey, event.RegQueryValue, event.OpenProcess:
		return pipeline.ClassNoisy
	}
	return pipeline.ClassNormal
}

func New(ctx context.Context, psnap ps.Snapshotter, config *config.Config) (*Probe, error) {
	ctx, cancel := context.WithCancel(ctx)

	p := &Probe{
		ctx:              ctx,
		cancelFunc:       cancel,
		psnap:            psnap,
		config:           config,
		kernelTrace:      libetw.NewKernelTrace(config),
		userTrace:        libetw.NewUserTrace(config),
		errs:             make(chan error, 200),
		filePathResolver: make(map[uint64]FileInfo),
		fcbPathResolver:  expirable.NewLRU[uint64, FileInfo](3000, nil, time.Minute*10),
		kcbPathResolver:  make(map[uint64]string),

		filePathStringCache: stringcache.New(),
		kcbPathStringCache:  stringcache.NewScoped(stringcache.CacheSize),

		enqueuedIORequests:   make(map[uint64]ioRequest),
		enqueuedRegSetValues: expirable.NewLRU[pair.Pair[uint32, string], *event.Event](50, nil, time.Second*10),

		regionProber: va.NewRegionProber(),
	}

	pipeConfig := pipeline.DefaultConfig(2)
	pipeConfig.RingSize = ringSize
	pipeConfig.Classifier = classifyEvent
	pipeConfig.Handler = p

	var err error
	p.pipeline, err = pipeline.New(pipeConfig)
	if err != nil {
		return nil, err
	}

	if config.EventSource.StackEnrichment {
		p.linker = NewCallstackLinker(p)
	}

	return p, nil
}
