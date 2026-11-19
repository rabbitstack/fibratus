/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package ps

import (
	"errors"
	"expvar"
	"maps"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	log "github.com/sirupsen/logrus"
)

// SystemPID designates the pid of the system process that acts as the container for system threads
const SystemPID uint32 = 4

var (
	// reapPeriod specifies the interval for triggering the housekeeping of dead processes
	reapPeriod = time.Minute * 2

	// dirtyPeriod specifies for how long the state of the terminated process
	// is retained in the dirty map to serve the events that arrive late
	dirtyPeriod = time.Second * 5

	// startSkew is the tolerance applied when comparing event timestamps with the process
	// start time. The start time is read from the OS, while the event timestamp is stamped
	// by the tracing session, so the two clocks may disagree slightly.
	startSkew = time.Millisecond * 100

	processLookupFailureCount = expvar.NewMap("process.lookup.failure.count")
	reapedProcesses           = expvar.NewInt("process.reaped")
	processCount              = expvar.NewInt("process.count")
	threadCount               = expvar.NewInt("process.thread.count")
	moduleCount               = expvar.NewInt("process.module.count")
	mmapCount                 = expvar.NewInt("process.mmap.count")
	pebReadErrors             = expvar.NewInt("process.peb.read.errors")
	processEnrichments        = expvar.NewInt("process.enrichments")
)

// Snapshotter is the interface that exposes a set of methods all process snapshotters have to satisfy. It stores the state
// of all running processes in the system including its threads, dynamically loaded libraries, handles/file descriptors
// and other metadata.
//
// The snapshotter is agnostic of the event layout. The events are converted into the process state types by the
// mappers before they are handed to the snapshotter.
type Snapshotter interface {
	// AddProcess appends a new process state to the snapshotter. If the state is derived
	// from the NT kernel logger events, it is enriched with extra metadata such as process' env
	// variables, handles, PE metadata for Windows binaries and so on. The process state that was
	// derived from the internal events only enriches the existing state, or creates the
	// state placeholder, if there is none.
	AddProcess(*pstypes.PS) error

	// RemoveProcess removes the process state from the snapshotter.
	RemoveProcess(pid uint32)

	// AddThread adds the thread to the process identified by the thread pid.
	AddThread(pstypes.Thread)

	// RemoveThread removes the thread from the given process.
	RemoveThread(pid uint32, tid uint32)

	// AddModule adds the module to the specified process.
	AddModule(pid uint32, mod pstypes.Module)

	// RemoveModule removes the module the given process.
	RemoveModule(pid uint32, addr va.Address)

	// AddMmap adds a new memory mapping (data memory-mapped file, image, or pagefile) to the specified process.
	AddMmap(pid uint32, mmap pstypes.Mmap)

	// RemoveMmap removes memory mapping at the given base address.
	RemoveMmap(pid uint32, addr va.Address)

	// Find attempts to retrieve process' state for the specified process identifier. Returns true
	// if the process was find in the state. Otherwise, returns false and constructs a fresh process
	// state by querying the OS via API functions.
	Find(pid uint32) (*pstypes.PS, bool)

	// FindModule traverses loaded modules of all processes in the snapshot and
	// if there is module with the specified base address, it returns its metadata.
	FindModule(addr va.Address) (*pstypes.Module, bool)

	// FindAllModules finds all unique modules across the snapshotter state.
	FindAllModules() map[string]pstypes.Module

	// FindAndPut attempts to retrieve process' state for the specified process identifier.
	// If the process is found, the snapshotter state is updated with the new process.
	FindAndPut(pid uint32) *pstypes.PS

	// Put inserts the process state into snapshotter.
	Put(*pstypes.PS)

	// Size returns the total number of process state items.
	Size() uint32

	// Close closes process snapshotter and disposes all allocated resources.
	Close() error
}

type snapshotter struct {
	sync.RWMutex
	procs map[uint32]*pstypes.PS

	dirty     map[uint32]*pstypes.PS
	dirtyLock sync.RWMutex

	quit      chan struct{}
	closeOnce sync.Once
	config    *config.Config

	hsnap handle.Snapshotter

	users *UserResolver

	capture bool
}

// NewSnapshotter returns a new instance of the process snapshotter.
func NewSnapshotter(hsnap handle.Snapshotter, config *config.Config) Snapshotter {
	s := &snapshotter{
		procs:  make(map[uint32]*pstypes.PS),
		dirty:  make(map[uint32]*pstypes.PS),
		quit:   make(chan struct{}),
		config: config,
		hsnap:  hsnap,
		users:  Users(),
	}

	go s.gcDeadProcesses()

	return s
}

// NewSnapshotterFromCapture restores the snapshotter state from the capture file.
func NewSnapshotterFromCapture(hsnap handle.Snapshotter, config *config.Config) Snapshotter {
	s := &snapshotter{
		procs:   make(map[uint32]*pstypes.PS),
		dirty:   make(map[uint32]*pstypes.PS),
		quit:    make(chan struct{}),
		config:  config,
		hsnap:   hsnap,
		users:   Users(),
		capture: true,
	}

	return s
}

func (s *snapshotter) AddProcess(proc *pstypes.PS) error {
	if proc == nil {
		return nil
	}

	if s.capture {
		s.addProcessFromCapture(proc)
		return nil
	}

	s.RLock()
	existing := s.procs[proc.PID]
	s.RUnlock()

	var err error
	if !proc.IsCreatedFromSystemLogger {
		// the internal events carry the process sequence number, so the
		// UUID is derived from it without querying the OS
		if proc.SeqNum != 0 {
			proc.InitUUID()
		}
	} else {
		// the sequence number that came with the internal event is
		// preferred over querying the OS for it, so inherit it before
		// the UUID is derived
		if existing != nil && !existing.IsCreatedFromSystemLogger && existing.Equals(proc, startSkew) {
			proc.InheritSeqNum(existing)
		}
		// the token attributes are queried only if the process state isn't going
		// to be enriched by the internal event that carries them. Enrichment is
		// best-effort
		err = s.populateProc(proc, existing == nil || existing.IsCreatedFromSystemLogger)
		// derive the UUID while the process is most likely alive. If it was
		// deferred until the first request, the process could be gone by
		// then, and the less robust variant of the UUID would be computed
		// for the same process instance
		proc.InitUUID()
	}

	s.Lock()
	defer s.Unlock()

	current := s.procs[proc.PID]

	if !proc.IsCreatedFromSystemLogger {
		switch {
		case current == nil:
			// no state yet, so keep the placeholder until the NT kernel logger events show up
			s.procs[proc.PID] = proc
			processCount.Add(1)
		case current.IsCreatedFromSystemLogger:
			// state exists derived from the core kernel events exists so we enrich it
			current.Merge(proc)
			// the sequence number from the internal event wins over the one
			// that may have been queried from the OS
			current.AssignUUID(proc)
		default:
			s.procs[proc.PID] = proc
		}
		return err
	}

	switch {
	case current == nil:
		processCount.Add(1)
	case !current.IsCreatedFromSystemLogger:
		// enrich the newly arrived process state with the state previously derived
		// from the internal event
		proc.Merge(current)
		// if the process UUID has been initialized when the internal event arrived,
		// reassign it to the current process state
		proc.AssignUUID(current)
		processEnrichments.Add(1)
	}

	// assign the parent reference
	if proc.Ppid != proc.PID {
		proc.Parent = s.findParentProc(proc)
	}
	s.procs[proc.PID] = proc

	return err
}

func (s *snapshotter) RemoveProcess(pid uint32) {
	s.Lock()
	defer s.Unlock()

	proc := s.procs[pid]
	if proc == nil {
		return
	}
	delete(s.procs, pid)
	processCount.Add(-1)

	// move the process to the dirty map. This is required
	// to prevent dropping process state from events when
	// TerminateProcess event is emitted before subsequent
	// events arrive
	s.dirtyLock.Lock()
	s.dirty[pid] = proc
	s.dirtyLock.Unlock()

	// schedule the removal. The pid can be reused in the
	// meantime, so the removal must not drop the dirty
	// state of the process that reused it
	time.AfterFunc(dirtyPeriod, func() {
		s.dirtyLock.Lock()
		defer s.dirtyLock.Unlock()
		if s.dirty[pid] == proc {
			delete(s.dirty, pid)
			log.Debugf("dirty process removed: %s. Dirty procs: %d", proc.Name, len(s.dirty))
		}
	})

	// resets the parent of all child processes
	for _, child := range s.procs {
		if child.Ppid == pid && child.PID != pid {
			child.Parent = nil
		}
	}
}

func (s *snapshotter) AddThread(thread pstypes.Thread) {
	proc := s.findProc(thread.Pid)
	// the thread rundown events can be delivered for the thread that
	// was previously added, so count only the threads that are new
	if proc != nil && proc.AddThread(thread) {
		threadCount.Add(1)
	}
}

func (s *snapshotter) RemoveThread(pid uint32, tid uint32) {
	proc := s.findProc(pid)
	if proc != nil && proc.RemoveThread(tid) {
		threadCount.Add(-1)
	}
}

func (s *snapshotter) AddModule(pid uint32, mod pstypes.Module) {
	proc := s.findProc(pid)
	// the module may be already present, e.g. the rundown event
	// is delivered for the module that was previously loaded. The
	// counter is bumped only if the module was really appended
	if proc != nil && proc.AddModule(mod) {
		moduleCount.Add(1)
	}
}

func (s *snapshotter) RemoveModule(pid uint32, addr va.Address) {
	proc := s.findProc(pid)
	if proc != nil && proc.RemoveModule(addr) {
		moduleCount.Add(-1)
	}
}

func (s *snapshotter) FindModule(addr va.Address) (*pstypes.Module, bool) {
	s.RLock()
	defer s.RUnlock()
	for _, proc := range s.procs {
		proc.RLock()

		idx := slices.IndexFunc(proc.Modules, func(mod pstypes.Module) bool {
			return mod.BaseAddress == addr
		})

		if idx >= 0 {
			mod := &proc.Modules[idx]
			proc.RUnlock()
			return mod, true
		}

		proc.RUnlock()
	}
	return nil, false
}

func (s *snapshotter) FindAllModules() map[string]pstypes.Module {
	s.RLock()
	defer s.RUnlock()

	mods := make(map[string]pstypes.Module)

	for _, proc := range s.procs {
		proc.RLock()
		for _, mod := range proc.Modules {
			if _, exists := mods[mod.Name]; !exists {
				mods[mod.Name] = mod
			}
		}
		proc.RUnlock()
	}
	return mods
}

func (s *snapshotter) AddMmap(pid uint32, mmap pstypes.Mmap) {
	proc := s.findProc(pid)
	if proc != nil {
		mmapCount.Add(1)
		proc.AddMmap(mmap)
	}
}

func (s *snapshotter) RemoveMmap(pid uint32, addr va.Address) {
	proc := s.findProc(pid)
	if proc != nil && proc.RemoveMmap(addr) {
		mmapCount.Add(-1)
	}
}

func (s *snapshotter) Close() error {
	s.closeOnce.Do(func() { close(s.quit) })
	return nil
}

func (s *snapshotter) Put(proc *pstypes.PS) {
	if proc != nil {
		s.Lock()
		defer s.Unlock()
		s.procs[proc.PID] = proc
	}
}

func (s *snapshotter) FindAndPut(pid uint32) *pstypes.PS {
	proc, ok := s.Find(pid)
	if !ok {
		s.Put(proc)
	}
	return proc
}

func (s *snapshotter) Find(pid uint32) (*pstypes.PS, bool) {
	s.RLock()
	ps, ok := s.procs[pid]
	s.RUnlock()
	if ok {
		return ps, true
	}
	if s.capture || pid == sys.InvalidProcessID {
		return nil, false
	}

	// check if the process is in dirty map
	s.dirtyLock.RLock()
	ps = s.dirty[pid]
	s.dirtyLock.RUnlock()
	if ps != nil {
		return ps, true
	}

	processLookupFailureCount.Add(strconv.Itoa(int(pid)), 1)

	// the OS API query is slow, so it must not run with the lock held
	return s.getProcSnapshot(pid), false
}

// findProc returns the state of the live process. The per-process state
// guards its own collections, so the snapshotter lock is held only for
// the lookup.
func (s *snapshotter) findProc(pid uint32) *pstypes.PS {
	s.RLock()
	defer s.RUnlock()
	return s.procs[pid]
}

// findParentProc resolves the parent process state. The parent pid may have been
// reused by an unrelated process, so when the parent sequence number is known,
// the candidate is accepted only if it is the same process instance. A terminated
// parent is not linked, which is consistent with orphaning the children when
// the parent process terminates. The caller must hold the snapshotter lock.
func (s *snapshotter) findParentProc(proc *pstypes.PS) *pstypes.PS {
	parent := s.procs[proc.Ppid]
	if parent == nil || proc.ParentSeqNum == 0 {
		return parent
	}
	if parent.IsUUIDExact() && parent.UUID() != proc.ParentUUID() {
		return nil
	}
	return parent
}

// getProcSnapshot builds the process state by querying the OS API. Returns
// the minimal process state if the process handle can't be opened. Otherwise,
// the process executable, parent id, start time, token information and PEB are
// attached to the process state.
func (s *snapshotter) getProcSnapshot(pid uint32) *pstypes.PS {
	proc := &pstypes.PS{
		PID:     pid,
		Ppid:    sys.InvalidProcessID,
		Threads: make(map[uint32]pstypes.Thread),
		Modules: make([]pstypes.Module, 0),
		Handles: make([]htypes.Handle, 0),
	}

	process, err := proc.Open()
	if err != nil {
		return proc
	}
	defer windows.CloseHandle(process) //nolint:errcheck

	// attempt to resolve fundamental process attributes
	_ = proc.ResolveFlags(process)
	_ = proc.ResolveParentID(process)
	_ = proc.ResolveStartTime(process)
	_ = proc.ResolveExecutable(process)

	// retrieve Portable Executable data
	proc.PE, _ = pe.ParseFileWithConfig(proc.Exe, s.config.PE)

	// obtain process token user information
	user, err := pstypes.GetTokenUserInformation(process)
	if err == nil {
		proc.SID = user.User.Sid.String()
		proc.Domain, proc.Username = splitDomainUser(s.users.GetUser(proc.SID))
	}

	// obtain process token integrity level
	var sidIntegrityLevel *windows.SID
	sidIntegrityLevel, proc.IsTokenElevated, err = pstypes.GetTokenIntegrityInformation(process)
	if err == nil {
		proc.TokenIntegrityLevel = sys.RidToString(sidIntegrityLevel)
	}

	// populate environment variables, command line, cwd and session id from PEB
	peb, err := ReadPEB(process)
	if err != nil {
		pebReadErrors.Add(1)
		return proc
	}
	proc.Envs = peb.GetEnvs()
	proc.Cmdline = peb.GetCommandLine()
	proc.SessionID = peb.GetSessionID()
	proc.Cwd = peb.GetCurrentWorkingDirectory()

	return proc
}

// populateProc augments the existing process state derived from the
// NT Kernel Logger provider with extra attributes, including the process
// token integrity level, the current working directory and env variables.
func (s *snapshotter) populateProc(proc *pstypes.PS, inspectToken bool) error {
	var err error
	var errs multierror.MultiError

	// retrieve process handles
	proc.Handles, err = s.hsnap.FindHandles(proc.PID)
	if err != nil {
		errs.Add(err)
	}
	// retrieve Portable Executable data
	proc.PE, err = pe.ParseFileWithConfig(proc.Exe, s.config.PE)
	if err != nil {
		errs.Add(err)
	}

	process, err := proc.Open()
	if err != nil {
		if errors.Is(err, windows.ERROR_NOT_FOUND) ||
			errors.Is(err, windows.ERROR_ACCESS_DENIED) ||
			errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil
		}
		return errs.Wrap(err)
	}
	defer windows.Close(process)

	// query token integrity info if not enriched by internal event
	if inspectToken {
		var sid *windows.SID
		sid, proc.IsTokenElevated, err = pstypes.GetTokenIntegrityInformation(process)
		if err != nil {
			errs.Add(err)
		} else {
			proc.TokenIntegrityLevel = sys.RidToString(sid)
		}
	}

	// try to read the PEB (Process Environment Block) to access
	// environment variables and the current working directory
	var peb *PEB
	peb, err = ReadPEB(process)
	if err != nil {
		pebReadErrors.Add(1)
		return errs.Wrap(err)
	}
	proc.Envs = peb.GetEnvs()
	proc.Cwd = peb.GetCurrentWorkingDirectory()

	return errs.Wrap()
}

func (s *snapshotter) Size() uint32 {
	s.RLock()
	defer s.RUnlock()
	return uint32(len(s.procs))
}

// gcDeadProcesses periodically scans the map of the snapshot's processes and removes
// any terminated processes from it. This guarantees that any leftovers are cleaned-up
// in case we miss process' terminate events.
func (s *snapshotter) gcDeadProcesses() {
	tick := time.NewTicker(reapPeriod)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			s.reap()
		case <-s.quit:
			return
		}
	}
}

func (s *snapshotter) reap() {
	// take the copy of the snapshot, so the OS calls don't
	// run with the lock held and block the event processing
	s.RLock()
	snap := make(map[uint32]*pstypes.PS, len(s.procs))
	maps.Copy(snap, s.procs)
	s.RUnlock()

	log.Debugf("scanning for dead processes on the snapshot of %d items", len(snap))

	dead := make([]uint32, 0)
	for pid := range snap {
		proc, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
		if err != nil {
			continue
		}
		if !sys.IsProcessRunning(proc) {
			dead = append(dead, pid)
		}
		_ = windows.CloseHandle(proc)
	}
	if len(dead) == 0 {
		return
	}

	var reaped int64
	s.Lock()
	defer s.Unlock()
	for _, pid := range dead {
		// the pid might have been reused in the meantime
		// by the new process, so make sure we're about to
		// delete the same state we have inspected
		if proc, ok := s.procs[pid]; ok && proc == snap[pid] {
			delete(s.procs, pid)
			reaped++
		}
	}

	if reaped > 0 {
		processCount.Add(-reaped)
		reapedProcesses.Add(reaped)
		log.Debugf("%d dead process(es) reaped", reaped)
	}
}

// addProcessFromCapture adds the process state restored from the capture file. There's
// nothing to enrich since the OS state doesn't correspond to the captured state.
func (s *snapshotter) addProcessFromCapture(proc *pstypes.PS) {
	if proc.PID == proc.Ppid || proc.PID == sys.InvalidProcessID {
		return
	}
	s.Lock()
	defer s.Unlock()
	if proc.Ppid != proc.PID {
		proc.Parent = s.procs[proc.Ppid]
	}
	if _, exists := s.procs[proc.PID]; !exists {
		processCount.Add(1)
	}
	s.procs[proc.PID] = proc
}
