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
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"path/filepath"
	"runtime"
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

// procTTLSeconds specifies the number of seconds
// a process is allowed to remain in the map before
// its handle and symbol resources are disposed
const procTTLSeconds = 15

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
// Debug Helper API.
type Symbolizer struct {
	config *config.Config
	procs  map[uint32]*process
	mu     sync.Mutex

	cleaner *time.Ticker
	purger  *time.Ticker
}

// NewSymbolizer builds a new instance of address symbolizer.
// It performs the initialization of symbol options, symbols
// handlers and modules for kernel address symbolization.
func NewSymbolizer(config *config.Config) *Symbolizer {
	if config.SymbolizeKernelAddresses {
		sys.SymLoadKernelModules(config.SymbolPaths)
	}
	sym := &Symbolizer{
		config:  config,
		procs:   make(map[uint32]*process),
		cleaner: time.NewTicker(time.Second),
		purger:  time.NewTicker(time.Minute * 5),
	}

	go sym.housekeep()

	return sym
}

func (s *Symbolizer) CanEnqueue() bool { return false }

func (s *Symbolizer) Close() {
	s.cleaner.Stop()
	s.purger.Stop()
	s.cleanAllSyms()
	if s.config.SymbolizeKernelAddresses {
		for _, dev := range sys.EnumDevices() {
			sys.SymUnloadModule(windows.CurrentProcess(), uint64(dev.Addr))
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
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		sys.SymCleanup(proc.handle)
		_ = windows.CloseHandle(proc.handle)
		delete(s.procs, pid)
		return true, nil
	}
	if e.IsLoadImage() || e.IsUnloadImage() {
		filename := e.GetParamAsString(kparams.FileName)
		// if the kernel driver is loaded or unloaded,
		// load/unload symbol handlers respectively
		if strings.ToLower(filepath.Ext(filename)) == ".sys" || e.Kparams.TryGetBool(kparams.FileIsDriver) {
			m, err := windows.UTF16PtrFromString(filename)
			if err != nil {
				return true, nil
			}
			runtime.LockOSThread()
			addr := e.Kparams.TryGetAddress(kparams.ImageBase)
			if e.IsLoadImage() {
				sys.SymLoadModule(windows.CurrentProcess(), 0, m, nil, addr.Uint64(), 0, 0, 0)
			} else {
				sys.SymUnloadModule(windows.CurrentProcess(), addr.Uint64())
			}
			runtime.UnlockOSThread()
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	addrs := e.Kparams.MustGetSliceAddrs(kparams.Callstack)
	e.Callstack.Init(len(addrs))
	if e.IsVirtualAlloc() || (e.IsCreateFile() && !e.IsCreateDisposition()) {
		// for high-volume events decorating
		// the frames with symbol information
		// is not viable. For this reason, the
		// frames are decorated in fast mode.
		// In this mode, symbolization is skipped
		s.pushFrames(addrs, e, true)
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	proc, ok := s.procs[e.PID]
	if !ok {
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_INFORMATION, false, e.PID)
		if err != nil {
			s.pushFrames(addrs, e, true)
			return err
		}
		// initialize symbol handler
		sys.SymSetOptions(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
		if !sys.SymInitialize(handle, s.config.SymbolPathsUTF16(), true) {
			s.pushFrames(addrs, e, true)
			return ErrSymInitialize(e.PID)
		}
		proc = &process{e.PID, handle, time.Now(), 1}
		s.procs[e.PID] = proc
	}

	// full symbolization
	s.pushFrames(addrs, e, false)
	proc.keepalive()

	return nil
}

func (s *Symbolizer) pushFrames(addrs []va.Address, e *kevent.Kevent, fast bool) {
	for _, addr := range addrs {
		e.Callstack.PushFrame(s.produceFrame(addr, e, fast))
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
// calling into Debug Helper API.
func (s *Symbolizer) produceFrame(addr va.Address, e *kevent.Kevent, fast bool) kevent.Frame {
	frame := kevent.Frame{Addr: addr}
	if addr.InSystemRange() {
		if s.config.SymbolizeKernelAddresses {
			frame.Module = sys.GetSymModuleName(windows.CurrentProcess(), addr.Uint64())
			frame.Symbol, frame.Offset = sys.GetSymName(windows.CurrentProcess(), addr.Uint64())
		}
		return frame
	}
	if fast && e.PS != nil {
		frame.Module = e.PS.FindModuleByVa(addr)
		if frame.Module == "unbacked" {
			frame.Module = e.PS.FindMappingByVa(addr)
		}
		return frame
	}

	proc, ok := s.procs[e.PID]
	if !ok {
		if e.PS != nil {
			frame.Module = e.PS.FindModuleByVa(addr)
		}
		return frame
	}
	mod := sys.GetSymModuleName(proc.handle, addr.Uint64())
	if mod == "?" && e.PS != nil {
		mod = e.PS.FindModuleByVa(addr)
	}
	if mod == "unbacked" {
		mod = e.PS.FindMappingByVa(addr)
	}
	frame.Module = mod
	frame.Symbol, frame.Offset = sys.GetSymName(proc.handle, addr.Uint64())
	return frame
}

func (s *Symbolizer) cleanSym() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, proc := range s.procs {
		if time.Now().Sub(proc.accessed).Seconds() > procTTLSeconds {
			symCleanups.Add(1)
			log.Debugf("deallocating symbol resources for pid %d. Accessed %d time(s)", proc.pid, proc.accesses)
			sys.SymCleanup(proc.handle)
			_ = windows.Close(proc.handle)
			delete(s.procs, proc.pid)
		}
	}
}

func (s *Symbolizer) cleanAllSyms() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, proc := range s.procs {
		sys.SymCleanup(proc.handle)
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
		}
	}
}
