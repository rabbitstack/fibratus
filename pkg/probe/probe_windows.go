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
	kcbPathResolver  map[uint64]string                // maps KCB (Key Control Block) pointer to registry path

	// stores pending I/O request packets
	enqueuedIORequests map[uint64]ioRequest

	// enqueuedRegSetValues keeps temporarily RegSetValue internal events by pid and base value name
	enqueuedRegSetValues *expirable.LRU[regValueKey, *event.Event]

	config *config.Config

	psnap ps.Snapshotter

	rs *config.RulesCompileResult

	wg         sync.WaitGroup
	ctx        context.Context
	cancelFunc context.CancelFunc

	errs chan error

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

// regValueKey identifies a pending internal RegSetValue event.
type regValueKey struct {
	pid  uint32
	name string // base name of the registry value
}

func (p *Probe) Init() error {
	if p.rs != nil {
		if p.config.EventSource.EnableThreadEvents {
			p.config.EventSource.EnableThreadEvents = p.rs.HasThreadEvents
		}
		// config.EventSource.EnableModuleEvents = config.EventSource.EnableModuleEvents && e.r.HasModuleEvents
		// config.EventSource.EnableNetEvents = config.EventSource.EnableNetEvents && e.r.HasNetworkEvents
		// config.EventSource.EnableRegistryEvents = config.EventSource.EnableRegistryEvents && (e.r.HasRegistryEvents || (config.Yara.Enabled && !config.Yara.SkipRegistry))
		// config.EventSource.EnableFileIOEvents = config.EventSource.EnableFileIOEvents && (e.r.HasFileEvents || (config.Yara.Enabled && !config.Yara.SkipFiles))
		// config.EventSource.EnableVAMapEvents = config.EventSource.EnableVAMapEvents && (e.r.HasVAMapEvents || (config.Yara.Enabled && !config.Yara.SkipMmaps))
		// config.EventSource.EnableMemEvents = config.EventSource.EnableMemEvents && (e.r.HasMemEvents || (config.Yara.Enabled && !config.Yara.SkipAllocs))
		// config.EventSource.EnableDNSEvents = config.EventSource.EnableDNSEvents && e.r.HasDNSEvents
		// config.EventSource.EnableAuditAPIEvents = config.EventSource.EnableAuditAPIEvents && e.r.HasAuditAPIEvents
	}
	// 	func dropSet(all []event.Type, keep eventPredicate) []event.Type {
	// 	return slices.DeleteFunc(slices.Clone(all), keep) // removes kept ones, leaving the drops
	// 	}
	// }
	if p.rs != nil {
		for _, typ := range event.AllTypes() {
			if typ.OnlyState() || typ.StateSnapshot() {
				continue
			}
			if typ == event.CreateProcess || typ == event.TerminateProcess ||
				typ == event.LoadModule || typ == event.UnloadModule {
				// always allow fundamental events
				continue
			}

			// allow events required for memory/file scanning
			// if typ == event.MapViewOfSection && config.Yara.Enabled && !config.Yara.SkipMmaps {
			// 	continue
			// }
			// if typ == event.VirtualAlloc && config.Yara.Enabled && !config.Yara.SkipAllocs {
			// 	continue
			// }
			// if typ == event.CreateFile && config.Yara.Enabled && !config.Yara.SkipFiles {
			// 	continue
			// }
			// if typ == event.RegSetValue && config.Yara.Enabled && !config.Yara.SkipRegistry {
			// 	continue
			// }

			// if !e.r.ContainsEvent(typ) {
			// 	config.EventSource.SetDropMask(typ)
			// }
		}
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
	if p.config.EventSource.EnableRegistryEvents {
		// p.userTrace.AddProvider(etw.WindowsKernelRegistryGUID, libetw.WithKeywords(etw.SetValueKeyword), libetw.WithEventFilterDescriptors(etw.EventFilterDescriptor{
		// 	Ptr:  uintptr(unsafe.Pointer(&etw.CaptureRegistryValue)),
		// 	Size: 4,
		// }))
		val := 0x2
		eventFilterDescriptor := etw.EventFilterDescriptor{
			Ptr:  uintptr(unsafe.Pointer(&val)),
			Size: 4,
		}
		p.userTrace.AddProvider(etw.WindowsKernelRegistryGUID, libetw.WithKeywords(etw.SetValueKeyword), libetw.WithEventFilterDescriptors(eventFilterDescriptor))
	}

	if p.config.EventSource.EnableDNSEvents {
		p.userTrace.AddProvider(etw.DNSClientGUID)
	}

	if p.config.EventSource.EnableAuditAPIEvents {
		p.userTrace.AddProvider(etw.KernelAuditAPICallsGUID, libetw.WithCallstack(p.config.EventSource.StackEnrichment))
	}

	return nil
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

	// Flush and stop user trace
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

	// Flush and stop kernel trace
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
	if eventType == event.RegSetValueInternal {
		panic(rec)
	}
	if p.config.EventSource.HasDropType(eventType) {
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
			callstack = rec.ReadCallstackInto(16, va.GetCallstack())
		)
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
	case event.RegOpenKey, event.RegQueryKey:

	case event.OpenProcess, event.OpenThread:

	case event.Unknown:
		return nil
	}

	switch eventType {
	case event.FileOpEnd:
		completed, err := p.completeIORequest(producerID, eventType, rec)
		if err != nil {
			return err
		}
		if !completed {
			return nil
		}
		return nil
	case event.MapViewOfSection, event.UnmapViewOfSection, event.MapViewSectionRundown, event.DeleteFile, event.SetFileInformation, event.RenameFile, event.EnumDirectory, event.ReadFile, event.WriteFile:
		fileinfo, found := p.resolveFileInfo(rec)
		evt, producer, err := p.pipeline.AcquireEvent(producerID, eventType)
		if err != nil {
			return err
		}
		evt.Parse(rec)
		if found {
			evt.AppendParam(params.FilePath, params.Path, fileinfo.Path)
			evt.AppendEnum(params.FileType, uint32(fileinfo.Type), fs.FileTypes)
		}
		producer.Publish()
		return nil
	case event.RegOpenKey, event.RegCreateKey, event.RegDeleteKey, event.RegQueryKey, event.RegQueryValue, event.RegSetValue, event.RegDeleteValue:
		path := p.resolveKCBPath(rec)
		if path == "" {
			break
		}

		evt, producer, err := p.pipeline.AcquireEvent(producerID, eventType)
		if err != nil {
			return err
		}
		evt.Parse(rec)
		_ = evt.Params.SetValue(params.RegPath, path)

		producer.Publish()
		return nil
	}

	producer := p.pipeline.Producer(producerID)
	evt := producer.Acquire(eventType)
	if evt == nil {
		return pipeline.ErrRingNoSlots
	}
	evt.Parse(rec)
	if evt.IsRegSetValueInternal() {
		panic(evt)
	}

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
func (p *Probe) completeIORequest(producerID pipeline.ProducerID, eventType event.Type, rec *etw.EventRecord) (bool, error) {
	var (
		disposition uint32
		status      uint32
	)

	// Dequeue the pending I/O packet
	irp := rec.ReadUint64(0)
	req, enqueued := p.enqueuedIORequests[irp]
	if !enqueued || req.rec.Header.Timestamp > rec.Header.Timestamp {
		return false, nil
	}
	defer req.rec.ReleasePool()
	delete(p.enqueuedIORequests, irp)

	// Drive the state management of active files
	object := req.rec.ReadUint64(8)
	opts := req.rec.ReadUint32(20)
	path := req.rec.ConsumeUTF16String(32)

	opts &= 0xFFFFFF
	p.filePathResolver[object] = FileInfo{Path: path, Type: fs.GetFileType(path, opts)}

	status = rec.ReadUint32(16)
	if windows.NTStatus(status) == windows.STATUS_REPARSE {
		// Inherit caller's create disposition
	} else {
		disposition = uint32(rec.ReadUint64(8))
	}

	// Publish the completed I/O request
	evt, producer, err := p.pipeline.AcquireEvent(producerID, eventType)
	if err != nil {
		return true, err
	}
	evt.Parse(req.rec)

	// Attach create disposition and NT status parameters
	evt.AppendParam(params.NTStatus, params.Status, status)
	evt.AppendEnum(params.FileOperation, disposition, fs.FileCreateDispositions)

	producer.Publish()

	return true, nil
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
		if !p.fcbPathResolver.Contains(key) {
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
		if err := p.psnap.Remove(evt); err != nil {
			return err
		}
	case event.CreateThread, event.ThreadRundown:
	case event.TerminateThread:
	case event.LoadModule, event.ModuleRundown, event.LoadModuleInternal:
	case event.UnloadModule:
	case event.RegSetValue, event.RegSetValueInternal:
		//p.handleRegSetValue(evt)
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

func (p *Probe) handleRegSetValue(evt *event.Event) {
	if evt.IsRegSetValueInternal() {
		// Park the internal RegSetValue event until the public
		// RegSetValue event for the same pid/value shows up
		path := evt.Params.MustGetString(params.RegPath)
		k := regValueKey{evt.PID, filepath.Base(path)}
		panic(k)
		p.enqueuedRegSetValues.Add(k, evt.Clone())
		return
	}

	// Returns and removes the parked internal event
	// matching e, or nil if there is none (or it already expired).
	// previously stored RegSetValueInternal event
	// is popped from the queue. RegSetValue can
	// be enriched with registry value type/data
	k := regValueKey{evt.PID, filepath.Base("")}
	e, ok := p.enqueuedRegSetValues.Peek(k)
	if !ok {
		// Try to read captured data from userspace
		//goto readValue
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
	return

	//readValue:
	if !evt.IsSuccess() {
		return
	}

	// Values within hidden keys cannot be read
	// if strings.HasSuffix(path, "\\") {
	// 	return
	// }

	// get the type/value of the registry key and append to parameters
	// rootkey, subkey := key.Format(path)
	// if rootkey == key.Invalid {
	// 	return
	// }

	//readValueOps.Add(1)
	// typ, val, err := rootkey.ReadValue(subkey)
	// if err != nil {
	// 	errno, ok := err.(windows.Errno)
	// 	if ok && (errno.Is(os.ErrNotExist) || err == windows.ERROR_ACCESS_DENIED) {
	// 		return e, nil
	// 	}
	// 	return e, ErrReadValue(rootkey.String(), path, err)
	// }
	// e.AppendEnum(params.RegValueType, typ, key.RegistryValueTypes)

	// switch typ {
	// case registry.SZ, registry.EXPAND_SZ:
	// 	e.AppendParam(params.RegData, params.UnicodeString, val)
	// case registry.MULTI_SZ:
	// 	e.AppendParam(params.RegData, params.Slice, val)
	// case registry.BINARY:
	// 	e.AppendParam(params.RegData, params.Binary, val)
	// case registry.QWORD:
	// 	e.AppendParam(params.RegData, params.Uint64, val)
	// case registry.DWORD:
	// 	e.AppendParam(params.RegData, params.Uint32, uint32(val.(uint64)))
	// }
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
		fcbPathResolver:  expirable.NewLRU[uint64, FileInfo](2500, nil, 0),
		kcbPathResolver:  make(map[uint64]string),

		enqueuedIORequests:   make(map[uint64]ioRequest),
		enqueuedRegSetValues: expirable.NewLRU[regValueKey, *event.Event](50, nil, time.Second*5),
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
