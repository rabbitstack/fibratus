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
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/convert"
	"github.com/rabbitstack/fibratus/pkg/util/threadcontext"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
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

	// symCacheHits counts the number of cache hits in the symbols cache
	symCacheHits = expvar.NewInt("symbolizer.cache.hits")

	// symCachedSymbols counts the number of cached symbol infos
	symCachedSymbols = expvar.NewInt("symbolizer.cached.symbols")

	// symModulesCount counts the number of loaded module exports
	symModulesCount = expvar.NewInt("symbolizer.modules.count")

	// symEnumModulesHits counts the number of hits from enumerated modules
	symEnumModulesHits = expvar.NewInt("symbolizer.enum.modules.hits")

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
	exports                    *ModuleExports
	minExportRVA, maxExportRVA uint32
	hasExports                 bool
}

func (m *module) isUnexported(rva va.Address) bool {
	if m.minExportRVA == 0 || m.maxExportRVA == 0 {
		return false
	}
	return rva.Uint64() < uint64(m.minExportRVA) || rva.Uint64() > uint64(m.maxExportRVA)
}

type syminfo struct {
	module        string
	symbol        string
	moduleAddress va.Address // base module address
}

// Symbolizer is responsible for converting raw addresses
// into symbol names and modules with the assistance of the
// export directory or symbol resolver.
type Symbolizer struct {
	config *config.Config
	procs  map[uint32]*process
	mods   map[uint32]map[va.Address]*module
	mu     sync.Mutex

	// symbols stores the mapping of stack
	// return address and the symbol information
	// identifying the originated call. It is populated
	// by the Debug Help API function when the module
	// doesn't exist in process state, and in addition
	// it is populated by each export directory symbol
	// resolution
	symbols map[uint32]map[va.Address]syminfo

	// exps stores resolved export directories
	exps *ExportsDirectoryCache

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
		mods:    make(map[uint32]map[va.Address]*module),
		symbols: make(map[uint32]map[va.Address]syminfo),
		cleaner: time.NewTicker(time.Second * 2),
		purger:  time.NewTicker(time.Minute * 5),
		quit:    make(chan struct{}, 1),
		enqueue: enqueue,
		exps:    NewExportsDirectoryCache(psnap),
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
	go sym.exps.purge()

	return sym
}

func (s *Symbolizer) CanEnqueue() bool { return s.enqueue }

func (s *Symbolizer) Close() {
	s.cleaner.Stop()
	s.purger.Stop()
	s.quit <- struct{}{}
	s.exps.quit <- struct{}{}
	s.cleanAllSyms()
	if s.config.SymbolizeKernelAddresses {
		for _, dev := range sys.EnumDevices() {
			s.r.UnloadModule(windows.CurrentProcess(), va.Address(dev.Addr))
		}
	}
}

func (s *Symbolizer) ProcessEvent(e *event.Event) (bool, error) {
	if e.IsTerminateProcess() {
		// release symbol handler and process handle
		pid := e.Params.MustGetPid()
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.mods, pid)
		delete(s.symbols, pid)
		// remove exports for this process
		s.exps.RemoveExports(e.GetParamAsString(params.Exe))
		symCachedSymbols.Add(-int64(len(s.symbols[pid])))
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
		filename := e.GetParamAsString(params.ImagePath)
		addr := e.Params.TryGetAddress(params.ImageBase)
		// if the kernel driver is loaded or unloaded,
		// load/unload symbol handlers respectively
		if (strings.ToLower(filepath.Ext(filename)) == ".sys" ||
			e.Params.TryGetBool(params.FileIsDriver)) && s.config.SymbolizeKernelAddresses {
			if e.IsLoadImage() {
				err := s.r.LoadModule(windows.CurrentProcess(), filename, addr)
				if err != nil {
					log.Errorf("unable to load symbol table for %s module: %v", filename, err)
				}
			} else {
				s.r.UnloadModule(windows.CurrentProcess(), addr)
			}
		}

		// remove module if it has been unmapped from the process VAS
		err := s.syncModules(e)
		if err != nil {
			log.Error(err)
		}
	}

	if !e.Params.Contains(params.Callstack) {
		return true, nil
	}
	defer e.Params.Remove(params.Callstack)

	err := s.processCallstack(e)
	if err != nil {
		callstackProcessErrors.Add(1)
	}

	return true, nil
}

// syncModules reconciles the state of loaded modules.
// When the module is unloaded from the process address
// space, its information is pruned from the cache.
// If the new module is loaded and not already present in
// the map, we get its export directory and insert
// into the map.
func (s *Symbolizer) syncModules(e *event.Event) error {
	base := e.Params.TryGetAddress(params.ImageBase)
	size := e.Params.TryGetUint64(params.ImageSize)

	if e.IsUnloadImage() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.mods[e.PID][base]; ok {
			symModulesCount.Add(-1)
			delete(s.mods[e.PID], base)
			// prune symbol entry from the cache if
			// the symbol address falls within the
			// unmapped module
			syms, ok := s.symbols[e.PID]
			if !ok {
				return nil
			}
			for addr := range syms {
				if addr >= base && addr <= base.Inc(size) {
					delete(s.symbols[e.PID], base)
				}
			}
		}
	}

	return nil
}

func (s *Symbolizer) processCallstack(e *event.Event) error {
	addrs := e.Params.MustGetSliceAddrs(params.Callstack)
	e.Callstack.Init(len(addrs))

	// skip stack enrichment for the events generated by the System process
	// except the LoadImage event which may prove to be useful when the driver
	// is loaded and the kernel address symbolization is enabled
	if e.IsSystemPid() && !e.IsLoadImage() {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if e.PS != nil {
		var (
			addr va.Address
			pid  uint32
		)

		// get the address that we want to symbolize
		switch e.Type {
		case event.CreateThread:
			pid = e.Params.MustGetPid()
			addr = e.Params.TryGetAddress(params.StartAddress)
		case event.SubmitThreadpoolWork, event.SubmitThreadpoolCallback:
			pid = e.PID
			addr = e.Params.TryGetAddress(params.ThreadpoolCallback)
		}

		// symbolize thread start or thread pool callback address
		// and resolve the module name that contains the function
		if addr != 0 {
			mod := e.PS.FindModuleByVa(addr)
			// perform lookup against parent modules
			if mod == nil && e.PS.Parent != nil {
				mod = e.PS.Parent.FindModuleByVa(addr)
			}
			symbol := s.symbolizeAddress(pid, addr, mod)

			if symbol != "" && symbol != "?" {
				switch e.Type {
				case event.CreateThread:
					e.Params.Append(params.StartAddressSymbol, params.UnicodeString, symbol)
				case event.SubmitThreadpoolWork, event.SubmitThreadpoolCallback:
					e.Params.Append(params.ThreadpoolCallbackSymbol, params.UnicodeString, symbol)

					ctx := e.Params.TryGetAddress(params.ThreadpoolContext)

					// if the callback resolves to one of the functions
					// that receive the CONTEXT structure as a parameter
					// try to read the thread context and resolve the
					// function address stored in the instruction pointer
					if ctx != 0 && threadcontext.IsParamOfFunc(symbol) {
						rip := threadcontext.Rip(pid, ctx)
						if rip != 0 {
							e.Params.Append(params.ThreadpoolContextRip, params.Address, rip.Uint64())

							m := e.PS.FindModuleByVa(rip)
							if m != nil {
								e.Params.Append(params.ThreadpoolContextRipModule, params.UnicodeString, m.Name)
							}

							sym := s.symbolizeAddress(pid, rip, m)
							if sym != "" && sym != "?" {
								e.Params.Append(params.ThreadpoolContextRipSymbol, params.UnicodeString, sym)
							}
						}
					}
				}
			}

			if mod != nil {
				switch e.Type {
				case event.CreateThread:
					e.Params.Append(params.StartAddressModule, params.UnicodeString, mod.Name)
				case event.SubmitThreadpoolWork, event.SubmitThreadpoolCallback:
					e.Params.Append(params.ThreadpoolCallbackModule, params.UnicodeString, mod.Name)
				}
			}
		}

		// try to resolve addresses from process
		// state and PE export directory data
		s.pushFrames(addrs, e)

		return nil
	}

	pid := e.StackPID()
	proc, ok := s.procs[pid]
	if !ok {
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_INFORMATION, false, pid)
		if err != nil {
			s.pushFrames(addrs, e)
			return err
		}
		// initialize symbol handler
		opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
		err = s.r.Initialize(handle, opts)
		if err != nil {
			s.pushFrames(addrs, e)
			return ErrSymInitialize(pid)
		}
		proc = &process{pid, handle, time.Now(), 1}
		s.procs[pid] = proc
	}

	s.pushFrames(addrs, e)

	proc.keepalive()

	return nil
}

// pushFrames populates the stack frames. The
// addresses slice contains the original return
// addresses where the first element is the
// most recent kernel return address that is
// pushed last into the event callstack.
func (s *Symbolizer) pushFrames(addrs []va.Address, e *event.Event) {
	for i := len(addrs) - 1; i >= 0; i-- {
		e.Callstack.PushFrame(s.produceFrame(addrs[i], e))
	}
}

// produceFrame fabrics a decorated stack frame.
// For return addresses residing in the kernel
// address space, the symbolization is always
// performed. All symbols are resolved from the
// PE export directory entries. If either the
// symbol or module are not resolved, then we
// fall back to Debug API.
func (s *Symbolizer) produceFrame(addr va.Address, e *event.Event) callstack.Frame {
	pid := e.StackPID()
	frame := callstack.Frame{PID: pid, Addr: addr}
	if addr.InSystemRange() {
		if s.config.SymbolizeKernelAddresses {
			frame.Module = s.r.GetModuleName(windows.CurrentProcess(), addr)
			frame.Symbol, frame.Offset = s.r.GetSymbolNameAndOffset(windows.CurrentProcess(), addr)
		}
		return frame
	}

	// did we hit this address previously?
	if sym, ok := s.symbols[pid]; ok {
		if symbol, ok := sym[addr]; ok {
			symCacheHits.Add(1)
			frame.Module, frame.Symbol, frame.ModuleAddress = symbol.module, symbol.symbol, symbol.moduleAddress
			return frame
		}
	}

	ps := e.PS

	// for process creation events initiated by
	// brokered processes, obtain the real parent
	// process state
	if e.IsSurrogateProcess() {
		var ok bool
		ok, ps = s.psnap.Find(e.Params.MustGetUint32(params.ProcessRealParentID))
		if !ok {
			ps = e.PS
		}
	}

	if ps != nil {
		mod := ps.FindModuleByVa(addr)
		// perform lookup against parent modules
		if mod == nil && ps.Parent != nil {
			mod = ps.Parent.FindModuleByVa(addr)
		}
		if mod == nil {
			// our last resort is to enumerate process modules
			modules := sys.EnumProcessModules(pid)
			for _, m := range modules {
				b := va.Address(m.BaseOfDll)
				size := uint64(m.SizeOfImage)
				if addr >= b && addr <= b.Inc(size) {
					mod = &pstypes.Module{
						Name:        m.Name,
						BaseAddress: b,
						Size:        size,
					}
					symEnumModulesHits.Add(1)
					break
				}
			}
		}

		if mod != nil {
			frame.Module = mod.Name
			frame.ModuleAddress = mod.BaseAddress
			m, ok := s.mods[pid][mod.BaseAddress]
			peOK := true
			if !ok {
				var exports *ModuleExports
				exports, peOK = s.exps.Exports(mod.Name)
				m = &module{
					hasExports: true,
					exports:    &ModuleExports{exps: make(map[uint32]string)},
				}
				if exports != nil {
					m.exports = exports
					m.hasExports = len(m.exports.exps) > 0
					exportRVAs := convert.MapKeysToSlice(m.exports.exps)
					if m.hasExports {
						m.minExportRVA, m.maxExportRVA = slices.Min(exportRVAs), slices.Max(exportRVAs)
					}
				} else {
					m.hasExports = false
				}
				symModulesCount.Add(1)
				s.cacheModule(e.PID, mod.BaseAddress, m)
			}
			rva := addr.Dec(mod.BaseAddress.Uint64())
			frame.Symbol = m.exports.SymbolFromRVA(rva)
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
		}

		if frame.Module != "" && frame.Symbol != "" {
			// store resolved symbol information in cache
			s.cacheSymbol(pid, addr, &frame)
			return frame
		}
	}

	debugHelpFallbacks.Add(1)

	// fallback to Debug Help API
	proc, ok := s.procs[pid]
	if !ok {
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_INFORMATION, false, pid)
		if err != nil {
			return frame
		}
		// initialize symbol handler
		opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
		err = s.r.Initialize(handle, opts)
		if err != nil {
			return frame
		}
		proc = &process{pid, handle, time.Now(), 1}
		s.procs[pid] = proc
	}

	proc.keepalive()

	if frame.Module == "" {
		mod := s.r.GetModuleName(proc.handle, addr)
		frame.Module = mod
		if frame.Module == "?" {
			frame.Module = "unbacked"
		}
	}
	if frame.Symbol == "" {
		frame.Symbol, frame.Offset = s.r.GetSymbolNameAndOffset(proc.handle, addr)
	}

	// store resolved symbol information in cache
	s.cacheSymbol(pid, addr, &frame)

	return frame
}

// symbolizeAddress resolves the given address to a symbol. If the symbol
// for this address was resolved previously, we fetch it from the cache.
// On the contrary, the symbol is first consulted in the export directory.
// If not found, the Debug Help API is used to symbolize the address.
func (s *Symbolizer) symbolizeAddress(pid uint32, addr va.Address, mod *pstypes.Module) string {
	if addr.InSystemRange() {
		return ""
	}

	symbol, ok := s.symbols[pid][addr]
	if !ok && mod != nil {
		// resolve symbol from the export directory
		exports, ok := s.exps.Exports(mod.Name)
		if !ok {
			goto fallback
		}
		rva := addr.Dec(mod.BaseAddress.Uint64())
		symbol.symbol = exports.SymbolFromRVA(rva)
	}

fallback:
	// try to get the symbol via Debug Help API
	if symbol.symbol == "" {
		proc, ok := s.procs[pid]
		if !ok {
			handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_INFORMATION, false, pid)
			if err != nil {
				return ""
			}

			// initialize symbol handler
			opts := uint32(sys.SymUndname | sys.SymCaseInsensitive | sys.SymAutoPublics | sys.SymOmapFindNearest | sys.SymDeferredLoads)
			err = s.r.Initialize(handle, opts)
			if err != nil {
				return ""
			}

			proc = &process{pid, handle, time.Now(), 1}
			s.procs[pid] = proc

			// resolve address to symbol
			symbol.symbol, _ = s.r.GetSymbolNameAndOffset(handle, addr)
			symbol.module = s.r.GetModuleName(handle, addr)
		} else {
			symbol.symbol, _ = s.r.GetSymbolNameAndOffset(proc.handle, addr)
			symbol.module = s.r.GetModuleName(proc.handle, addr)
			proc.keepalive()
		}
	}

	if symbol.module == "" && mod != nil {
		symbol.module = mod.Name
	}

	// cache the resolved symbol
	if sym, ok := s.symbols[pid]; ok {
		if _, ok := sym[addr]; !ok {
			s.symbols[pid][addr] = symbol
		}
	} else {
		s.symbols[pid] = map[va.Address]syminfo{addr: symbol}
	}

	return symbol.symbol
}

func (s *Symbolizer) cacheModule(pid uint32, addr va.Address, m *module) {
	if mod, ok := s.mods[pid]; ok {
		if _, ok := mod[addr]; !ok {
			s.mods[pid][addr] = m
		}
	} else {
		s.mods[pid] = map[va.Address]*module{addr: m}
	}
}

func (s *Symbolizer) cacheSymbol(pid uint32, addr va.Address, frame *callstack.Frame) {
	if sym, ok := s.symbols[pid]; ok {
		if _, ok := sym[addr]; !ok {
			symCachedSymbols.Add(1)
			s.symbols[pid][addr] = syminfo{module: frame.Module, symbol: frame.Symbol, moduleAddress: frame.ModuleAddress}
		}
	} else {
		symCachedSymbols.Add(1)
		s.symbols[pid] = map[va.Address]syminfo{addr: {module: frame.Module, symbol: frame.Symbol, moduleAddress: frame.ModuleAddress}}
	}
}

func (s *Symbolizer) cleanSym() {
	s.mu.Lock()
	defer s.mu.Unlock()
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
