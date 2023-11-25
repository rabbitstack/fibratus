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
	"golang.org/x/sys/windows"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrSymInitialize is thrown if the process symbol handler fails to initialize
var ErrSymInitialize = func(pid uint32) error {
	return fmt.Errorf("unable to initialize symbol handler for pid %d", pid)
}

// callstackProcessErrors counts callstack process errors
var callstackProcessErrors = expvar.NewInt("callstack.process.errors")

// Symbolizer is responsible for converting raw addresses
// into symbol names and modules with the assistance of the
// Debug Helper API.
type Symbolizer struct {
	config *config.Config
	procs  map[uint32]windows.Handle
}

// NewSymbolizer builds a new instance of address symbolizer.
// It performs the initialization of symbol options, symbols
// handlers and modules for kernel address symbolization.
func NewSymbolizer(config *config.Config) *Symbolizer {
	sys.SymLoadKernelModules(config.SymbolPaths)
	return &Symbolizer{
		config: config,
		procs:  make(map[uint32]windows.Handle),
	}
}

func (s *Symbolizer) ProcessEvent(e *kevent.Kevent) (bool, error) {
	if !e.Kparams.Contains(kparams.Callstack) {
		return true, nil
	}
	defer e.Kparams.Remove(kparams.Callstack)
	err := s.processCallstack(e)
	if err != nil {
		callstackProcessErrors.Add(1)
	}
	if e.IsTerminateProcess() {
		// release symbol handler and process handle
		pid := e.Kparams.MustGetPid()
		proc := s.procs[pid]
		sys.SymCleanup(proc)
		_ = windows.CloseHandle(proc)
		delete(s.procs, pid)
	}
	if e.IsLoadImage() || e.IsUnloadImage() {
		filename := e.GetParamAsString(kparams.FileName)
		if strings.ToLower(filepath.Ext(filename)) == ".sys" || e.Kparams.TryGetBool(kparams.FileIsDriver) {
			// if the kernel driver is loaded or unloaded,
			// load/unload symbol handlers respectively
			m, err := windows.UTF16PtrFromString(filename)
			if err != nil {
				return true, nil
			}
			addr := e.Kparams.TryGetAddress(kparams.ImageBase)
			if e.IsLoadImage() {
				sys.SymLoadModule(windows.CurrentProcess(), 0, m, nil, addr.Uint64(), 0, 0, 0)
			} else {
				sys.SymUnloadModule(windows.CurrentProcess(), addr.Uint64())
			}
		}
	}
	return true, nil
}

func (s *Symbolizer) processCallstack(e *kevent.Kevent) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// reserve callstack capacity
	addrs := e.Kparams.MustGetSliceAddrs(kparams.Callstack)
	e.Callstack.Init(len(addrs))
	if e.IsVirtualAlloc() {
		// virtual alloc requests can produce
		// a considerable amount of events. To
		// this extent, we can only afford
		// decorating the frames when the fast
		// mode is on. Sadly, fast mode can't
		// resolve symbol names.
		s.pushFrames(addrs, e, true)
		return nil
	}
	proc, ok := s.procs[e.PID]
	if ok && proc == windows.InvalidHandle {
		s.pushFrames(addrs, e, true)
		return nil
	}
	if !ok {
		var err error
		proc, err = windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_INFORMATION, false, e.PID)
		if err != nil {
			// to avoid pressure on the OpenProcess call
			// if the process object can't be acquired
			s.procs[e.PID] = windows.InvalidHandle
			s.pushFrames(addrs, e, true)
			return err
		}
		s.procs[e.PID] = proc
	}

	// initialize symbol handler
	sys.SymSetOptions(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
	if !sys.SymInitialize(proc, s.config.SymbolPathsUTF16(), true) {
		// if we can't initialize the symbol handler
		// let's resort to fast frame enrichment which
		// doesn't require Debug Helper interaction
		s.pushFrames(addrs, e, true)
		return ErrSymInitialize(e.PID)
	}
	defer sys.SymCleanup(proc)

	s.pushFrames(addrs, e, false)

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
// is enriched with module and symbol name, and
// memory section information such as allocation
// size and protection type on the region of pages.
func (s *Symbolizer) produceFrame(addr va.Address, e *kevent.Kevent, fast bool) kevent.Frame {
	frame := kevent.Frame{Addr: addr}
	if addr.InSystemRange() {
		frame.Module = sys.GetSymModuleName(windows.CurrentProcess(), addr.Uint64())
		frame.Symbol, frame.Offset = sys.GetSymName(windows.CurrentProcess(), addr.Uint64())
		return frame
	}
	if fast && e.PS != nil {
		frame.Module = e.PS.FindModuleByVa(addr)
		return frame
	}

	proc, ok := s.procs[e.PID]
	if !ok {
		if e.PS != nil {
			frame.Module = e.PS.FindModuleByVa(addr)
		}
		return frame
	}
	mod := sys.GetSymModuleName(proc, addr.Uint64())
	if mod == "?" && e.PS != nil {
		mod = e.PS.FindModuleByVa(addr)
	}
	frame.Module = mod
	frame.Symbol, frame.Offset = sys.GetSymName(proc, addr.Uint64())

	region := va.VirtualQuery(proc, addr.Uint64())
	if region != nil {
		frame.AllocationSize = region.Size
		frame.Protection = region.ProtectMask()
		if frame.Module == "?" && region.IsMapped() {
			frame.Module = region.GetMappedFile()
		}
	}
	return frame
}
