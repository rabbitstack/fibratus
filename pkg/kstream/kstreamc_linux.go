/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package kstream

import (
	"bytes"
	"embed"
	"errors"
	"expvar"
	"fmt"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/rabbitstack/fibratus/internal/procfs"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/util/limit"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	// kprobeFilename represents the kprobe object file name that is embedded via the go:embed directive
	kprobeFilename = "kprobe.o"
	// rawTracepointSysExit is the raw tracepoint to which the program is attached
	rawTracepointSysExit = "sys_exit"
)

//go:embed kprobe.o
var kprog embed.FS

var (
	// errKprobeNotEmbedded defines the error for the missing kprobe object file in the binary embedded section
	errKprobeNotEmbedded = errors.New("kprobe object file was not embedded or couldn't be read")
	// lostPerfEvents computes lost event samples per CPU
	lostPerfEvents = expvar.NewMap("kevent.lost.perf.events")

	discarderFailedInsertions = expvar.NewMap("kstream.discarders.failed.insertions")
)

type kstreamConsumer struct {
	// objs contains a collection of programs and maps that
	// are defined in the eBPF object file
	objs *ebpf.Collection
	// spec contains metadata about eBPF objects collection
	spec *ebpf.CollectionSpec

	// perfReader is responsible for consuming inbound
	// raw data blobs that are pushed from kernel space
	// when a particular syscall is invoked
	perfReader *perf.Reader

	// tracepoints represents the raw tracepoint where
	// the program is attached
	tracepoint link.Link

	maps  Maps
	errs  chan error
	kevts chan *kevent.Kevent

	config *config.Config

	sequencer *kevent.Sequencer

	filter filter.Filter
}

// NewConsumer fabrics a new ebpf-based event stream consumer.
func NewConsumer(config *config.Config) (Consumer, error) {
	// TODO: check kernel version
	b, err := kprog.ReadFile(kprobeFilename)
	if err != nil {
		return nil, errKprobeNotEmbedded
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	// increase the rlimit of the current process to provide
	// sufficient space for locking memory for eBPF maps
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, limit.WithInfinity()); err != nil {
		return nil, fmt.Errorf("failed to increase temporary rlimit: %w", err)
	}

	// load precompiled objects into the kernel
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: btoi(config.Kstream.EnableVerifierLogging),
			LogSize:  config.Kstream.VerifierLogsize,
		},
		Maps: ebpf.MapOptions{},
	}
	var objs *ebpf.Collection
	objs, err = ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("unable to load kprobe: %w", err)
	}
	maps, err := ToMaps(objs.Maps)
	if err != nil {
		return nil, err
	}

	var (
		keventsBlacklist = makeKeventBlacklist(config.Kstream.BlacklistKevents)
		commsBlacklist   = makeImageBlacklist(config.Kstream.BlacklistImages)
	)

	// populate tracer programs. This step consists of
	// traversing the collection of ebpf programs and
	// indexing the ktype number to the corresponding
	// program file descriptor.
	for _, progSpec := range spec.Programs {
		ktype := ktypes.FromProg(progSpec.Name)
		if ktype == ktypes.UnknownKtype || keventsBlacklist.has(ktype) {
			continue
		}
		// obtain the prog fd
		prog, ok := objs.Programs[progSpec.Name]
		if !ok {
			continue
		}
		// associate ktype with its tracer prog
		if err := maps.Put(Tracers, ktype.RawID(), uint32(prog.FD())); err != nil {
			return nil, err
		}
	}

	// populate discarders map with process image names.
	// Any event that is originated by the process image
	// present in the discarders map is dropped in the raw
	// syscall tracepoint hook
	for _, comm := range commsBlacklist {
		key := NewDiscarderKey(comm)
		if err := maps.Put(Discarders, key, key); err != nil {
			discarderFailedInsertions.Add(err.Error(), 1)
		}
	}
	// populate kpar specs map
	for _, kevtInfo := range ktypes.GetKtypesMeta() {
		ktype := ktypes.KeventNameToKtype(kevtInfo.Name)
		if ktype == ktypes.UnknownKtype {
			continue
		}
		if err := maps.Put(KparSpecs, ktype.RawID(), NewKparsValue(kevtInfo.Kpars)); err != nil {
			return nil, err
		}
	}

	kconsumer := &kstreamConsumer{
		objs:      objs,
		spec:      spec,
		maps:      maps,
		config:    config,
		kevts:     make(chan *kevent.Kevent),
		errs:      make(chan error, 1000),
		sequencer: kevent.NewSequencer(),
	}

	return kconsumer, nil
}

// OpenKstream attaches the eBPF program to the raw tracepoint for
// intercepting all syscall exit events and polls the perf ring buffer
// for raw samples.
func (k *kstreamConsumer) OpenKstream() error {
	watermark := k.config.Kstream.Watermark
	perCPUBuffer := k.config.Kstream.RingBufferSize
	if watermark > perCPUBuffer {
		watermark = perCPUBuffer / 2
	}
	var err error
	readerOpts := perf.ReaderOptions{
		Watermark: watermark,
	}
	perfMap := k.maps.GetMap(Perf)
	k.perfReader, err = perf.NewReaderWithOptions(perfMap, perCPUBuffer, readerOpts)
	if err != nil {
		return err
	}
	// attaches the prog to raw tracepoint
	progName := rawTracepointSysExit + "_tracepoint"
	rawTracepointProg := k.objs.Programs[progName]
	if rawTracepointProg == nil {
		return fmt.Errorf("missing program %s", progName)
	}
	k.tracepoint, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: rawTracepointSysExit, Program: rawTracepointProg})
	if err != nil {
		return err
	}

	// start consuming from perf ring buffer
	go func() {
		for {
			record, err := k.perfReader.Read()
			if err != nil {
				if perf.IsClosed(err) {
					log.Info("perf ring buffer is closing")
					return
				}
				k.errs <- err
				continue
			}
			if record.LostSamples > 0 {
				lostPerfEvents.Add(strconv.Itoa(record.CPU), int64(record.LostSamples))
				continue
			}
			rawSample := record.RawSample
			if err := k.processKevent(rawSample); err != nil {
				failedKevents.Add(err.Error(), 1)
				k.errs <- err
			}
		}
	}()

	return nil
}

func (k kstreamConsumer) CloseKstream() error {
	// disable the raw tracepoint
	if err := k.tracepoint.Close(); err != nil {
		return err
	}
	// release prog collection
	k.objs.Close()
	return k.perfReader.Close()
}

func (k kstreamConsumer) Errors() chan error {
	return k.errs
}

func (k kstreamConsumer) Events() chan *kevent.Kevent {
	return k.kevts
}

func (k *kstreamConsumer) SetFilter(filter filter.Filter) {
	k.filter = filter
}

func (k kstreamConsumer) processKevent(rawSample []byte) error {
	header := kevent.HeaderFromRawSample(rawSample)
	if header == nil {
		return nil
	}
	kevt := kevent.New(
		k.sequencer.Get(),
		header.Pid,
		header.Tid,
		uint8(header.CPU),
		ktypes.Ktype(header.Type),
		time.Unix(0, int64(header.Timestamp)),
		nil,
	)
	k.kevts <- kevt

	k.sequencer.Increment()

	return nil
}

func (k kstreamConsumer) produceParams(rawSample []byte, header *kevent.Header) map[string]*kevent.Kparam {
	return nil
}

func btoi(b bool) uint32 {
	if b {
		return uint32(1)
	}
	return 0
}

func makeKeventBlacklist(kevents []string) blacklist {
	keventsBlacklist := make(blacklist)
	for _, name := range kevents {
		if ktype := ktypes.KeventNameToKtype(name); ktype != ktypes.UnknownKtype {
			keventsBlacklist[ktype] = name
		}
	}
	return keventsBlacklist
}

func makeImageBlacklist(images []string) []string {
	return append(images, procfs.SelfComm())
}
