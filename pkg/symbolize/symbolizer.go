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
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/convert"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// ErrSymInitialize is thrown if the process symbol handler fails to initialize
var ErrSymInitialize = func(pid uint32) error {
	return fmt.Errorf("unable to initialize symbol handler for pid %d", pid)
}

var (
	// callstackProcessErrors counts callstack process errors
	callstackProcessErrors = expvar.NewInt("symbolizer.process.errors")

	// symCleanups counts the number of symbol cleanups
	symCleanups = expvar.NewInt("symbolizer.symbol.cleanups")
	// modCleanups counts the number of module cleanups
	modCleanups = expvar.NewInt("symbolizer.module.cleanups")

	// symCacheHits counts the number of cache hits in the symbols cache
	symCacheHits = expvar.NewInt("symbolizer.cache.hits")

	// symModulesCount counts the number of loaded module exports
	symModulesCount = expvar.NewInt("symbolizer.modules.count")

	// debugHelpFallbacks counts how many times we Debug Help API was called
	// to resolve symbol information since we fail to do this from process
	// modules and PE export directory data
	debugHelpFallbacks = expvar.NewInt("symbolizer.debughelp.fallbacks")
)

// parsePeFile wraps the PE parsing function to permit
// overriding the function in unit tests.
var parsePeFile = func(name string, option ...pe.Option) (*pe.PE, error) {
	return pe.ParseFile(name, pe.WithSections(), pe.WithExports())
}

// procTTL specifies the number of interval
// a process is allowed to remain in the map before
// its handle and symbol resources are disposed
var procTTL = 15 * time.Second

// modTTL maximum time for the module to remain in
// the state until all its exports are removed
var modTTL = 8 * time.Minute

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

type module struct {
	exports                    map[uint32]string
	accessed                   time.Time
	minExportRVA, maxExportRVA uint32
	hasExports                 bool
}

func (m *module) keepalive() {
	m.accessed = time.Now()
}

func (m *module) isUnexported(rva va.Address) bool {
	if m.minExportRVA == 0 || m.maxExportRVA == 0 {
		return false
	}
	return rva.Uint64() < uint64(m.minExportRVA) || rva.Uint64() > uint64(m.maxExportRVA)
}

// Symbolizer is responsible for converting raw addresses
// into symbol names and modules with the assistance of the
// symbol resolver.
type Symbolizer struct {
	config *config.Config
	procs  map[uint32]*process
	mods   map[va.Address]*module
	mu     sync.Mutex

	// symbols stores the mapping of stack
	// return address and the symbol information
	// identifying the originated call. It is populated
	// by the Debug Help API function when the module
	// doesn't exist in process state. Subsequent
	// calls to the produceFrame method will inspect
	// this cache whenever the module is not located
	// in process state
	symbols map[uint32]map[va.Address]string

	r     Resolver
	psnap ps.Snapshotter

	cleaner *time.Ticker
	purger  *time.Ticker

	quit chan struct{}

	enqueue bool
}

// NewSymbolizer builds a new instance of address symbolizer.
// It performs the initialization of symbol options, symbols
// handlers and modules for kernel address symbolization.
func NewSymbolizer(r Resolver, psnap ps.Snapshotter, config *config.Config, enqueue bool) *Symbolizer {
	sym := &Symbolizer{
		config:  config,
		procs:   make(map[uint32]*process),
		mods:    make(map[va.Address]*module),
		symbols: make(map[uint32]map[va.Address]string),
		cleaner: time.NewTicker(time.Second * 2),
		purger:  time.NewTicker(time.Minute * 5),
		quit:    make(chan struct{}, 1),
		enqueue: enqueue,
		r:       r,
		psnap:   psnap,
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
		delete(s.symbols, pid)
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
		addr := e.Kparams.TryGetAddress(kparams.ImageBase)
		// if the kernel driver is loaded or unloaded,
		// load/unload symbol handlers respectively
		if (strings.ToLower(filepath.Ext(filename)) == ".sys" ||
			e.Kparams.TryGetBool(kparams.FileIsDriver)) && s.config.SymbolizeKernelAddresses {
			if e.IsLoadImage() {
				err := s.r.LoadModule(windows.CurrentProcess(), filename, addr)
				if err != nil {
					log.Errorf("unable to load symbol table for %s module: %v", filename, err)
				}
			} else {
				s.r.UnloadModule(windows.CurrentProcess(), addr)
			}
		}

		// remove module if it has been unmapped from
		// all process VAS. If the new module is loaded
		// populate its export directory entries
		err := s.syncModules(e)
		if err != nil {
			log.Error(err)
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

// syncModules reconciles the state of loaded modules.
// When the module is unloaded from all processes in
// the snapshost state, its exports map is pruned. If
// the new module is loaded and not already present in
// the map, we parse its export directory and insert
// into the map.
func (s *Symbolizer) syncModules(e *kevent.Kevent) error {
	filename := e.GetParamAsString(kparams.FileName)
	addr := e.Kparams.TryGetAddress(kparams.ImageBase)
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.IsUnloadImage() {
		ok, _ := s.psnap.FindModule(addr)
		if !ok {
			symModulesCount.Add(-1)
			delete(s.mods, addr)
		}
		// remove executable images
		if strings.EqualFold(filepath.Ext(filename), ".exe") {
			delete(s.mods, addr)
		}
		return nil
	}
	if s.mods[addr] != nil {
		return nil
	}
	px, err := parsePeFile(filename, pe.WithSections(), pe.WithExports())
	if err != nil {
		return fmt.Errorf("unable to parse PE exports for module [%s]: %v", filename, err)
	}
	symModulesCount.Add(1)
	m := &module{exports: px.Exports, accessed: time.Now(), hasExports: true}
	exportRVAs := convert.MapKeysToSlice(m.exports)
	if len(exportRVAs) > 0 {
		m.minExportRVA, m.maxExportRVA = slices.Min(exportRVAs), slices.Max(exportRVAs)
	} else {
		m.hasExports = false
	}
	s.mods[addr] = m
	return nil
}

func (s *Symbolizer) processCallstack(e *kevent.Kevent) error {
	addrs := e.Kparams.MustGetSliceAddrs(kparams.Callstack)
	e.Callstack.Init(len(addrs))

	// skip stack enrichment for the events generated by the System process
	// except the LoadImage event which may prove to be useful when the driver
	// is loaded and the kernel address symbolization is enabled
	if e.IsSystemPid() && !e.IsLoadImage() {
		return nil
	}

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

	if e.PS != nil {
		// try to resolve addresses from process
		// state and PE export directory data
		s.pushFrames(addrs, e, false, true)
		return nil
	}

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

// pushFrames populates the stack frames. The
// addresses slice contains the original return
// addresses where the first element is the
// most recent kernel return address that is
// pushed last into the event callstack.
func (s *Symbolizer) pushFrames(addrs []va.Address, e *kevent.Kevent, fast, lookupExport bool) {
	for i := len(addrs) - 1; i >= 0; i-- {
		e.Callstack.PushFrame(s.produceFrame(addrs[i], e, fast, lookupExport))
	}
}

// produceFrame fabrics a decorated stack frame.
// For return addresses residing in the kernel
// address space, the symbolization is always
// performed. For userspace address range, if
// fast mode is enabled, the frame is solely
// decorated with the module name by iterating
// through modules contained in the process
// state. All symbols are resolved from the
// PE export directory entries. If either the
// symbol or module are not resolved, then we
// fallback to Debug API.
func (s *Symbolizer) produceFrame(addr va.Address, e *kevent.Kevent, fast, lookupExport bool) kevent.Frame {
	frame := kevent.Frame{Addr: addr}
	if addr.InSystemRange() {
		if s.config.SymbolizeKernelAddresses {
			frame.Module = s.r.GetModuleName(windows.CurrentProcess(), addr)
			frame.Symbol, frame.Offset = s.r.GetSymbolNameAndOffset(windows.CurrentProcess(), addr)
		}
		return frame
	}
	if fast {
		if e.PS != nil {
			mod := e.PS.FindModuleByVa(addr)
			if mod != nil {
				frame.Module = mod.Name
			}
			if frame.Module == "unbacked" || frame.Module == "" {
				frame.Module = e.PS.FindMappingByVa(addr)
			}
			if lookupExport {
				frame.Symbol = s.resolveSymbolFromExportDirectory(addr, mod)
			}
			return frame
		}
		return frame
	}

	if e.PS != nil {
		mod := e.PS.FindModuleByVa(addr)
		// perform lookup against parent modules
		if mod == nil && e.PS.Parent != nil {
			mod = e.PS.Parent.FindModuleByVa(addr)
		}
		if mod != nil {
			frame.Module = mod.Name
			m, ok := s.mods[mod.BaseAddress]
			peOK := true
			if !ok {
				// parse export directory to resolve symbols
				m = &module{exports: make(map[uint32]string), accessed: time.Now(), hasExports: true}
				px, err := parsePeFile(mod.Name, pe.WithSections(), pe.WithExports())
				if err != nil {
					peOK = false
					m.hasExports = false
				} else {
					m.exports = px.Exports
					m.hasExports = len(m.exports) > 0
					exportRVAs := convert.MapKeysToSlice(m.exports)
					if m.hasExports {
						m.minExportRVA, m.maxExportRVA = slices.Min(exportRVAs), slices.Max(exportRVAs)
					}
				}
				symModulesCount.Add(1)
				s.mods[mod.BaseAddress] = m
			}
			rva := addr.Dec(mod.BaseAddress.Uint64())
			frame.Symbol = symbolFromRVA(rva, m.exports)
			// permit unknown symbols for executable modules
			if frame.Symbol == "" && strings.EqualFold(filepath.Ext(mod.Name), ".exe") {
				frame.Symbol = "?"
			}
			// empirical observations revealed that if the syscall
			// is performed within the DLL unexported symbol, its RVA
			// is not in the range of exported symbols RVAs. Mark the
			// symbol as unknown. Likewise, if the module doesn't export
			// any symbols, don't try resolving symbol information with
			// Debug Help API
			if frame.Symbol == "" && (m.isUnexported(rva) || (!m.hasExports && peOK)) {
				frame.Symbol = "?"
			}
			// keep to module alive from purger
			m.keepalive()
		}
		if frame.Module != "" && frame.Symbol != "" {
			return frame
		}
	}

	// did we hit this address previously?
	if sym, ok := s.symbols[e.PID]; ok && sym[addr] != "" {
		symCacheHits.Add(1)
		n := strings.Split(sym[addr], "!")
		if len(n) > 1 {
			frame.Module, frame.Symbol = n[0], n[1]
		}
	}
	if frame.Module != "" && frame.Symbol != "" {
		return frame
	}

	debugHelpFallbacks.Add(1)

	// fallback to Debug Help API
	proc, ok := s.procs[e.PID]
	if !ok {
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_INFORMATION, false, e.PID)
		if err != nil {
			return frame
		}
		// initialize symbol handler
		opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
		err = s.r.Initialize(handle, opts)
		if err != nil {
			return frame
		}
		proc = &process{e.PID, handle, time.Now(), 1}
		s.procs[e.PID] = proc
	}

	proc.keepalive()

	if frame.Module == "" {
		mod := s.r.GetModuleName(proc.handle, addr)
		if mod == "?" && e.PS != nil {
			mod = e.PS.FindMappingByVa(addr)
		}
		frame.Module = mod
		if frame.Module == "?" {
			frame.Module = "unbacked"
		}
	}
	if frame.Symbol == "" {
		frame.Symbol, frame.Offset = s.r.GetSymbolNameAndOffset(proc.handle, addr)
	}

	// store resolved symbol information in cache
	sym := frame.Module + "!" + frame.Symbol
	if mod, ok := s.symbols[e.PID]; ok {
		if _, ok := mod[addr]; !ok {
			s.symbols[e.PID][addr] = sym
		}
	} else {
		s.symbols[e.PID] = map[va.Address]string{addr: sym}
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
	px, err := parsePeFile(mod.Name, pe.WithSections(), pe.WithExports())
	if err != nil {
		return ""
	}
	rva := addr.Dec(mod.BaseAddress.Uint64())
	return symbolFromRVA(rva, px.Exports)
}

// symbolFromRVA finds the closest export address before RVA.
func symbolFromRVA(rva va.Address, exports map[uint32]string) string {
	var exp uint32
	for f := range exports {
		if uint64(f) <= rva.Uint64() {
			if exp < f {
				exp = f
			}
		}
	}
	if exp != 0 {
		sym, ok := exports[exp]
		if ok && sym == "" {
			return "?"
		}
		return sym
	}
	return ""
}

func (s *Symbolizer) cleanSym() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for addr, m := range s.mods {
		if time.Since(m.accessed) > modTTL {
			modCleanups.Add(1)
			symModulesCount.Add(-1)
			log.Debugf("removing module exports for addr [%s]", addr)
			delete(s.mods, addr)
		}
	}
	for _, proc := range s.procs {
		if time.Since(proc.accessed) > procTTL {
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
