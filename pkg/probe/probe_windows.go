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
	"runtime"
	"sync"
	"time"
	"unsafe"

	libetw "github.com/rabbitstack/fibratus/internal/etw"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/bitmap"

	errs "github.com/rabbitstack/fibratus/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/smarty/go-disruptor"
)

type Probe struct {
	kernelTrace *libetw.KernelTrace
	userTrace   *libetw.UserTrace

	filePathResolver map[uint64]*FileInfo // maps file object address to file info
	fcbPathResolver  map[uint64]*FileInfo // maps FCB (File Control Block) key to file info
	kcbPathResolver  map[uint64]string    // maps KCB (Key Control Block) address to registry path

	// stores pending CreateFile I/O request packets
	ioRequestPackets map[uint64]irp

	config *config.Config

	psnap ps.Snapshotter

	rs       *config.RulesCompileResult
	dropMask bitmap.Bitmap[event.Type] // discarded events bit mask

	wg         sync.WaitGroup
	ctx        context.Context
	cancelFunc context.CancelFunc

	errs chan error

	disruptor disruptor.Disruptor
}

func (p *Probe) Init() error {
	if p.rs != nil {
		if p.config.ProbeConfig.EnableThreadEvents {
			p.config.ProbeConfig.EnableThreadEvents = p.rs.HasThreadEvents
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
	func dropSet(all []event.Type, keep eventPredicate) []event.Type {
	return slices.DeleteFunc(slices.Clone(all), keep) // removes kept ones, leaving the drops
	}
}
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
	if p.config.ProbeConfig.EnableRegistryEvents {
		p.userTrace.AddProvider(etw.WindowsKernelRegistryGUID, libetw.WithKeywords(etw.SetValueKeyword), libetw.WithEventFilterDescriptors(etw.EventFilterDescriptor{
			Ptr:  uintptr(unsafe.Pointer(&etw.CaptureRegistryValue)),
			Size: 4,
		}))
	}

	if p.config.ProbeConfig.EnableDNSEvents {
		p.userTrace.AddProvider(etw.DNSClientGUID)
	}

	if p.config.ProbeConfig.EnableAuditAPIEvents {
		p.userTrace.AddProvider(etw.KernelAuditAPICallsGUID, libetw.WithCallstack(p.config.ProbeConfig.StackEnrichment))
	}

	return nil
}

func (p *Probe) Start() error {
	err := p.kernelTrace.Start()
	if errors.Is(err, errs.ErrTraceAlreadyRunning) {

	}

	go func() {
		p.wg.Add(1)
		defer p.wg.Done()
		p.userTrace.Process(func(r *etw.EventRecord) error {
			return p.processEvent(r)
		}, p.errs)
	}()

	go func() {
		p.wg.Add(1)
		defer p.wg.Done()
		p.kernelTrace.Process(func(r *etw.EventRecord) error {
			return p.processEvent(r)
		}, p.errs)
	}()

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			defer func() {
				if r := recover(); r != nil {
					buf := make([]byte, 1<<20)
					n := runtime.Stack(buf, true)
					log.Fatalf("panic in event processing goroutine: %v\n%s", r, buf[:n])

					time.Sleep(5 * time.Second)

					os.Exit(1)
				}
			}()

			select {
			case <-p.ctx.Done():
				return
			case err := <-p.errs:
				log.Errorf(" %v", err)
			}

		}
	}()

	return nil
}

func (p *Probe) processEvent(r *etw.EventRecord) error {
	eventType := event.TypeFromEventRecord(r)

	switch eventType {
	case event.RegKCBRundown, event.RegCreateKCB:
		kcb := r.ReadUint64(16)
		path := r.ConsumeUTF16String(24)
		p.kcbPathResolver[kcb] = path

	case event.RegDeleteKCB:
		kcb := r.ReadUint64(16)
		delete(p.kcbPathResolver, kcb)

	case event.RegOpenKey:
		// allow/deny
	case event.CreateFile:

	case event.Unknown:
		return nil
	default:
		var evt *event.Event
		if p.dropMask.Has(eventType) {
			return nil
		}

		evt = event.New(r)
		seq := p.disruptor.TryReserve(1)
		if seq == disruptor.ErrCapacityUnavailable {
			return nil
		}
		ring[seq&ringMask] = evt
		p.disruptor.Commit(seq, seq)
	}

	return nil
}

func (p *Probe) handleEvent(evt *event.Event) error {
	return nil
}

func (p *Probe) Handle(lower, upper int64) {
	for seq := lower; seq <= upper; seq++ {
		e := ring[seq&ringMask]
		if err := p.handleEvent(e); err != nil {
			p.errs <- err
		}

		// dispatch to event listeners
		// dispatch to consumers
	}
}

func New(config *config.Config) (*Probe, error) {
	p := &Probe{
		config:      config,
		kernelTrace: libetw.NewKernelTrace(config),
		userTrace:   libetw.NewUserTrace(config),
	}

	var err error
	p.disruptor, err = disruptor.New(
		disruptor.Options.BufferCapacity(ringCapacity),
		disruptor.Options.WriterCount(2), // two session threads write concurrently
		disruptor.Options.NewHandlerGroup(p),
	)
	if err != nil {
		return nil, err
	}

	return p, nil
}
