/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package symbolize

import (
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrSymInitialize is thrown if the process symbol handler fails to initialize
var ErrSymInitialize = func(pid uint32) error {
	return fmt.Errorf("unable to initialize symbol handler for pid %d", pid)
}

// callstackProcessErrors counts callstack process errors
var callstackProcessErrors = expvar.NewInt("symbolizer.process.errors")

// symCleanups counts the number of symbol cleanups
var symCleanups = expvar.NewInt("symbolizer.symbol.cleanups")

// procTTL specifies the number of interval
// a process is allowed to remain in the map before
// its handle and symbol resources are disposed
var procTTL = 15 * time.Second

type process struct {
	pid      uint32
	handle   windows.Handle
	accessed time.Time
	accesses uint64
}

func (p *process) keepalive() {
	p.accessed = time.Now()
	p.accesses++
}

// Symbolizer is responsible for converting raw addresses
// into symbol names and modules with the assistance of the
// symbol resolver.
type Symbolizer struct {
	config *config.Config
	procs  map[uint32]*process
	mu     sync.Mutex

	r Resolver

	cleaner *time.Ticker
	purger  *time.Ticker

	quit chan struct{}

	enqueue bool
}

// NewSymbolizer builds a new instance of address symbolizer.
// It performs the initialization of symbol options, symbols
// handlers and modules for kernel address symbolization.
func NewSymbolizer(r Resolver, config *config.Config, enqueue bool) *Symbolizer {
	sym := &Symbolizer{
		config:  config,
		procs:   make(map[uint32]*process),
		cleaner: time.NewTicker(time.Second),
		purger:  time.NewTicker(time.Minute * 5),
		quit:    make(chan struct{}, 1),
		enqueue: enqueue,
		r:       r,
	}

	if config.SymbolizeKernelAddresses {
		opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics)
		err := r.Initialize(windows.CurrentProcess(), opts)
		if err != nil {
			log.Errorf("unable to initialize symbol handler for the current process: %v", err)
		}
		devs := sys.EnumDevices()
		for _, dev := range devs {
			_ = r.LoadModule(windows.CurrentProcess(), dev.Filename, va.Address(dev.Addr))
		}
	}

	go sym.housekeep()

	return sym
}

func (s *Symbolizer) CanEnqueue() bool { return s.enqueue }

func (s *Symbolizer) Close() {
	s.cleaner.Stop()
	s.purger.Stop()
	s.quit <- struct{}{}
	s.cleanAllSyms()
	if s.config.SymbolizeKernelAddresses {
		for _, dev := range sys.EnumDevices() {
			s.r.UnloadModule(windows.CurrentProcess(), va.Address(dev.Addr))
		}
	}
}

func (s *Symbolizer) ProcessEvent(e *kevent.Kevent) (bool, error) {
	if e.IsTerminateProcess() {
		// release symbol handler and process handle
		pid := e.Kparams.MustGetPid()
		s.mu.Lock()
		defer s.mu.Unlock()
		proc, ok := s.procs[pid]
		if !ok {
			return true, nil
		}
		s.r.Cleanup(proc.handle)
		_ = windows.CloseHandle(proc.handle)
		delete(s.procs, pid)
		return true, nil
	}
	if e.IsLoadImage() || e.IsUnloadImage() {
		filename := e.GetParamAsString(kparams.FileName)
		// if the kernel driver is loaded or unloaded,
		// load/unload symbol handlers respectively
		if strings.ToLower(filepath.Ext(filename)) == ".sys" || e.Kparams.TryGetBool(kparams.FileIsDriver) {
			addr := e.Kparams.TryGetAddress(kparams.ImageBase)
			if e.IsLoadImage() {
				err := s.r.LoadModule(windows.CurrentProcess(), filename, addr)
				if err != nil {
					log.Errorf("unable to load symbol table for %s module: %v", filename, err)
				}
			} else {
				s.r.UnloadModule(windows.CurrentProcess(), addr)
			}
		}
	}
	if !e.Kparams.Contains(kparams.Callstack) {
		return true, nil
	}
	defer e.Kparams.Remove(kparams.Callstack)
	err := s.processCallstack(e)
	if err != nil {
		callstackProcessErrors.Add(1)
	}
	return true, nil
}

func (s *Symbolizer) processCallstack(e *kevent.Kevent) error {
	addrs := e.Kparams.MustGetSliceAddrs(kparams.Callstack)
	e.Callstack.Init(len(addrs))
	if e.IsCreateFile() && e.IsOpenDisposition() {
		// for high-volume events decorating
		// the frames with symbol information
		// is not viable. For this reason, the
		// frames are decorated in fast mode.
		// In this mode, symbolization is skipped
		s.pushFrames(addrs, e, true, false)
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	proc, ok := s.procs[e.PID]
	if !ok {
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_INFORMATION, false, e.PID)
		if err != nil {
			s.pushFrames(addrs, e, true, true)
			return err
		}
		// initialize symbol handler
		opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
		err = s.r.Initialize(handle, opts)
		if err != nil {
			s.pushFrames(addrs, e, true, true)
			return ErrSymInitialize(e.PID)
		}
		proc = &process{e.PID, handle, time.Now(), 1}
		s.procs[e.PID] = proc
	}

	// perform full symbolization
	s.pushFrames(addrs, e, false, true)
	proc.keepalive()

	return nil
}

func (s *Symbolizer) pushFrames(addrs []va.Address, e *kevent.Kevent, fast, lookupExport bool) {
	for _, addr := range addrs {
		e.Callstack.PushFrame(s.produceFrame(addr, e, fast, lookupExport))
	}
}

// produceFrame fabrics a decorated stack frame.
// For return addresses residing in the kernel
// address space, the symbolization is always
// performed. For userspace address range, if
// fast mode is enabled, the frame is solely
// decorated with the module name by iterating
// through modules contained in the process
// state. If fast mode is not enabled, the frame
// is enriched with module and symbol name by
// calling into Debug Helper API. Finally, export
// directory is consulted for the symbol name if
// the standard symbol resolver methods fail to
// retrieve this information.
func (s *Symbolizer) produceFrame(addr va.Address, e *kevent.Kevent, fast, lookupExport bool) kevent.Frame {
	frame := kevent.Frame{Addr: addr, Module: "unbacked"}
	if addr.InSystemRange() {
		if s.config.SymbolizeKernelAddresses {
			frame.Module = s.r.GetModuleName(windows.CurrentProcess(), addr)
			frame.Symbol, frame.Offset = s.r.GetSymbolNameAndOffset(windows.CurrentProcess(), addr)
		}
		return frame
	}
	if fast && e.PS != nil {
		mod := e.PS.FindModuleByVa(addr)
		if mod != nil {
			frame.Module = mod.Name
		}
		if frame.Module == "unbacked" {
			frame.Module = e.PS.FindMappingByVa(addr)
		}
		if lookupExport {
			frame.Symbol = s.resolveSymbolFromExportDirectory(addr, mod)
		}
		return frame
	}

	proc, ok := s.procs[e.PID]
	if !ok {
		if e.PS != nil {
			mod := e.PS.FindModuleByVa(addr)
			if mod != nil {
				frame.Module = mod.Name
			}
			frame.Symbol = s.resolveSymbolFromExportDirectory(addr, mod)
		}
		return frame
	}
	module := s.r.GetModuleName(proc.handle, addr)
	if module == "?" && e.PS != nil {
		if mod := e.PS.FindModuleByVa(addr); mod != nil {
			module = mod.Name
		}
	}
	if (module == "?" || module == "unbacked") && e.PS != nil {
		module = e.PS.FindMappingByVa(addr)
	}
	frame.Module = module
	frame.Symbol, frame.Offset = s.r.GetSymbolNameAndOffset(proc.handle, addr)
	if frame.Symbol == "?" {
		frame.Symbol = s.resolveSymbolFromExportDirectory(addr, e.PS.FindModuleByVa(addr))
	}
	return frame
}

// resolveSymbolFromExportDirectory parses the module PE
// export directory  and attempts to locate the closest
// symbol before the relative virtual callstack address.
func (s *Symbolizer) resolveSymbolFromExportDirectory(addr va.Address, mod *pstypes.Module) string {
	if mod == nil {
		return ""
	}
	p, err := pe.ParseFile(mod.Name, pe.WithSections(), pe.WithExports())
	if err != nil {
		return ""
	}
	var exp uint32
	rva := addr.Dec(mod.BaseAddress.Uint64())
	// find the closest export address before RVA
	for f := range p.Exports {
		if uint64(f) <= rva.Uint64() {
			if exp < f {
				exp = f
			}
		}
	}
	if exp != 0 {
		return p.Exports[exp]
	}
	return ""
}

func (s *Symbolizer) cleanSym() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, proc := range s.procs {
		if time.Now().Sub(proc.accessed) > procTTL {
			symCleanups.Add(1)
			log.Debugf("deallocating symbol resources for pid %d. Accessed %d time(s)", proc.pid, proc.accesses)
			s.r.Cleanup(proc.handle)
			_ = windows.Close(proc.handle)
			delete(s.procs, proc.pid)
		}
	}
}

func (s *Symbolizer) cleanAllSyms() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, proc := range s.procs {
		s.r.Cleanup(proc.handle)
		_ = windows.Close(proc.handle)
	}
	s.procs = make(map[uint32]*process)
}

func (s *Symbolizer) housekeep() {
	for {
		select {
		case <-s.cleaner.C:
			s.cleanSym()
		case <-s.purger.C:
			s.cleanAllSyms()
		case <-s.quit:
			return
		}
	}
}

func (s *Symbolizer) procsSize() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.procs)
}
