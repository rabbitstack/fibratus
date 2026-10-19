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
	"os"
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
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/rabbitstack/fibratus/pkg/util/pair"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"

	log "github.com/sirupsen/logrus"
)

const maxEnqueuedIORequests = 200

const ringSize = 1 << 16

type Probe struct {
	PlatformProbe

	kernelTrace *libetw.KernelTrace
	userTrace   *libetw.UserTrace

	filePathResolver map[uint64]FileInfo              // maps file object pointer to file info
	fcbPathResolver  *expirable.LRU[uint64, FileInfo] // maps FCB (File Control Block) pointer to file info

	kcbPathResolver map[uint64]string // maps KCB (Key Control Block) pointer to registry path

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
}

// ioRequest acts as a scratch area for the pending IRP request
// that is used as a signal to promote the file operation.
// The memory buffer backing the event record is valid until
// the callback returns. Any state that needs to outlive the
// buffer lifetime must copy it safely.
type ioRequest struct {
	rec *etw.EventRecord // keeps the original CreateFile event record
	buf []byte           // keeps the data buffer alive
}

func (p *Probe) Init(rs *config.RulesCompileResult) error {
	var enableDNS bool
	var enableRegistry bool
	var enableAuditAPI bool
	p.rs = rs

	if rs != nil {
		enableDNS = rs.HasDNSEvents
		enableRegistry = rs.HasRegistryEvents
		enableAuditAPI = rs.HasAuditAPIEvents

		// Configure drop types if the rule engine is enabled, which is
		// the default for sensor mode. For any event not present in the
		// rule set, the bitmap rejects it is offloaded from the session
		// buffers
		drops := slices.DeleteFunc(event.AllTypes(), func(t event.Type) bool {
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
		})

		p.config.EventSource.AddDropTypes(drops...)
		p.kernelTrace.SetKernelEventFlags(p.toKernelEventFlags(rs))
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

	// in a similar vein, Windows Kernel Registry provider publishes
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

			time.Sleep(5 * time.Second)

			os.Exit(1)
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

	if p.linker != nil {
		p.linker.close()
	}

	p.cancelFunc()
	p.wg.Wait()

	return multierror.Wrap(errs...)
}

// processEvent is the entry point for every ETW event record delivered by the
// producer. Depending on the event type, the record is either committed to the
// ring buffer, parked until a related event arrives, used for state management
// or discarded.
func (p *Probe) processEvent(producerID pipeline.ProducerID, rec *etw.EventRecord) error {
	eventType := event.TypeFromEventRecord(rec)

	if p.config.EventSource.HasDropType(eventType) {
		return nil
	}

	pid := rec.Header.ProcessID
	if event.IsCurrentProcDropped(pid) && rec.Header.ProviderID != etw.WindowsKernelProcessGUID {
		return nil
	}

	switch eventType {
	case event.CreateFile:
		return p.initIORequest(rec)
	case event.CloseFile:
		object := rec.ReadUint64(8)
		delete(p.filePathResolver, object)
		return nil
	case event.FileRundown:
		object := rec.ReadUint64(0)
		path := rec.ConsumeUTF16String(8)
		p.filePathResolver[object] = FileInfo{Path: path, Type: fs.GetFileType(path, 0)}
		return nil
	case event.StackWalk:
		var (
			ts        = rec.ReadUint64(0)
			pid       = rec.ReadUint32(8)
			tid       = rec.ReadUint32(12)
			callstack = rec.ReadCallstackInto(16, va.GetCallstackFromPool())
		)
		if event.IsCurrentProcDropped(pid) {
			return nil
		}
		// Links the callstack carried by a StackWalk event with the
		// event that triggered it. If the CreateFile event is still
		// pending, it claims the callstack when it is published to
		// the ring buffer
		if p.isIOEnqueued(ts) {
			p.linker.reserve(ts, pid, tid, callstack)
			return nil
		}
		p.linker.Link(ts, pid, tid, callstack)
		return nil
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

	switch eventType {
	case event.FileOpEnd:
		return p.completeIORequest(producerID, rec)
	case event.MapViewOfSection, event.UnmapViewOfSection, event.MapViewSectionRundown, event.DeleteFile, event.SetFileInformation, event.RenameFile, event.EnumDirectory, event.ReadFile, event.WriteFile:
		return p.pipeline.Publish(producerID, eventType, func(evt *event.Event) {
			evt.Parse(rec)

			fileinfo, found := p.resolveFileInfo(rec)
			if !found {
				return
			}

			path := fileinfo.Path
			if evt.IsEnumDirectory() {
				// Concatenate file name or wildcard characters
				path = filepath.Join(path, evt.GetParamAsString(params.FilePath))
			}
			evt.AppendParam(params.FilePath, params.Path, path)
			evt.AppendEnum(params.FileType, uint32(fileinfo.Type), fs.FileTypes)
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
				path = key.ConcatPaths(root, subkey)
			} else {
				path = root
			}
		}

		if (eventType == event.RegOpenKey || eventType == event.RegQueryKey || eventType == event.RegQueryValue) &&
			!p.isRegPathApproved(path) {
			return nil
		}

		return p.pipeline.Publish(producerID, eventType, func(evt *event.Event) {
			evt.Parse(rec)
			_ = evt.Params.SetValue(params.RegPath, path)
		})
	case event.OpenProcess, event.OpenThread:
		pid := rec.ReadUint32(0)
		if !p.isExecutablePathApproved(pid, eventType == event.OpenThread && rec.Header.ProcessID != pid) {
			return nil
		}
	}

	producer := p.pipeline.Producer(producerID)
	evt := producer.Acquire(eventType)
	if evt == nil {
		return pipeline.ErrRingNoSlots
	}
	evt.Parse(rec)

	producer.Publish()

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
		disposition uint32
		status      uint32
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
	path := fs.GetDevMapper().Convert(req.rec.ConsumeUTF16String(32))

	opts &= 0xFFFFFF
	p.filePathResolver[object] = FileInfo{Path: path, Type: fs.GetFileType(path, opts)}

	status = rec.ReadUint32(16)
	if windows.NTStatus(status) == windows.STATUS_REPARSE {
		// Inherit caller's create disposition
		disposition = opts >> 24
	} else {
		disposition = uint32(rec.ReadUint64(8))
	}

	if !p.isFileApproved(path, disposition) {
		if p.linker != nil {
			p.linker.releaseReservation(req.rec.Header.Timestamp)
		}
		return nil
	}
	return p.pipeline.Publish(producerID, event.CreateFile, func(evt *event.Event) {
		evt.Parse(req.rec)
		// Attach create disposition and NT status parameters
		evt.AppendParam(params.NTStatus, params.Status, status)
		evt.AppendEnum(params.FileOperation, disposition, fs.FileCreateDispositions)
	})
}

// resolveFileInfo tries FileObject first  as authoritative, always populated on Create/
// Rundown and then falls back to FileKey works even if you missed the Create,
// e.g. mid-session attach, as long as some later op event backfilled it.
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
		// backfill the FCB map opportunistically. FileKey
		// never appears on Create/Rundown, only on op events — so this is
		// the only place it can be populated. Only write once so we don't
		// keep overwriting with (possibly reused) later resolutions.
		if rec.Header.EventDescriptor.Opcode == event.RenameFileID {
			if p.fcbPathResolver.Contains(key) {
				p.fcbPathResolver.Remove(key)
			}
			p.fcbPathResolver.Add(key, file)
		} else if !p.fcbPathResolver.Contains(key) {
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

	if baseKey, exists := p.kcbPathResolver[kcb]; exists {
		path := rec.ConsumeUTF16String(24)
		return key.ConcatPaths(baseKey, path)
	}

	return ""
}

func (p *Probe) isIOEnqueued(ts uint64) bool {
	for _, req := range p.enqueuedIORequests {
		if req.rec.Header.Timestamp == ts {
			return true
		}
	}
	return false
}

func (p *Probe) handleEvent(evt *event.Event) error {
	switch evt.Type {
	case event.MapViewSectionRundown, event.MapViewOfSection:
		// if err := p.handleMapViewSection(evt); err != nil {
		// 	return err
		// }
	case event.UnmapViewOfSection:
		// if err := p.handleUnmapViewSection(evt); err != nil {
		// 	return err
		// }
	case event.CreateProcess, event.CreateProcessInternal, event.ProcessRundown, event.ProcessRundownInternal:
		if err := p.handleCreateProcess(evt); err != nil {
			return err
		}
	case event.TerminateProcess:
		if err := p.removeProcess(evt); err != nil {
			return err
		}
	case event.CreateThread, event.ThreadRundown:
	case event.TerminateThread:
	case event.OpenProcess, event.OpenThread:
		pid, err := evt.Params.GetPid()
		if err != nil {
			return err
		}
		proc := p.psnap.FindAndPut(pid)
		if proc != nil {
			evt.AppendParam(params.Exe, params.Path, proc.Exe)
			evt.AppendParam(params.ProcessName, params.AnsiString, proc.Name)
		}
	case event.LoadModule, event.ModuleRundown, event.LoadModuleInternal:
		if err := p.handleLoadModule(evt); err != nil {
			return err
		}
	case event.UnloadModule:
		if err := p.removeModule(evt); err != nil {
			return err
		}
	case event.RegSetValue, event.RegSetValueInternal:
		p.handleRegSetValue(evt)
	case event.VirtualAlloc:
	case event.VirtualFree:
	case event.Accept, event.Connect, event.Send, event.Recv, event.Reconnect, event.Disconnect, event.Retransmit:
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

	if p.config.EventSource.StackEnrichment && evt.Type.WaitStack() {
		if event := p.linker.Put(evt); event != nil {
			return p.dispatchEvent(event)
		}
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

func (p *Probe) dispatchEvents(evts ...*event.Event) {
	for _, evt := range evts {
		p.dispatchEvent(evt)
	}
}

func (p *Probe) handleCreateProcess(evt *event.Event) error {
	if err := p.psnap.Write(evt); err != nil {
		return err
	}
	return nil
}

func (p *Probe) removeProcess(evt *event.Event) error {
	if err := p.psnap.Remove(evt); err != nil {
		return err
	}
	return nil
}

func (p *Probe) handleLoadModule(evt *event.Event) error {
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

func (p *Probe) Handle(evt *event.Event) {
	if err := p.handleEvent(evt); err != nil {
		select {
		case p.errs <- err:
		default:
		}
	}
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

		enqueuedIORequests:   make(map[uint64]ioRequest),
		enqueuedRegSetValues: expirable.NewLRU[pair.Pair[uint32, string], *event.Event](50, nil, time.Second*10),
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

// classifyEvent assigns the shedding priority of an event type. Events that
// build or tear down state (process, thread, module, the rundowns that seed
// them, and the internal RegSetValue that enriches the public one) must never
// be shed, or the process snapshot drifts and every later lookup misses.
// Everything else is ClassNormal. Once their volume is measured, move the
// high-volume types (file, registry, network) to pipeline.ClassNoisy so they
// are the first to go under pressure.
func classifyEvent(t event.Type) pipeline.ShedClass {
	switch t {
	case event.CreateProcess, event.CreateProcessInternal, event.ProcessRundown, event.ProcessRundownInternal, event.TerminateProcess,
		event.CreateThread, event.ThreadRundown, event.TerminateThread,
		event.LoadModule, event.ModuleRundown, event.LoadModuleInternal, event.UnloadModule,
		event.RegSetValueInternal:
		return pipeline.ClassState
	}
	if t == event.CreateFile || t == event.RegOpenKey {
		return pipeline.ClassNoisy
	}
	return pipeline.ClassNormal
}
