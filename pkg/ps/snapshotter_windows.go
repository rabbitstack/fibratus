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
	"expvar"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	log "github.com/sirupsen/logrus"
)

// SystemPID designates the pid of the system process that acts as the container for system threads
const SystemPID uint32 = 4

var (
	// reapPeriod specifies the interval for triggering the housekeeping of dead processes
	reapPeriod = time.Minute * 2

	processLookupFailureCount = expvar.NewMap("process.lookup.failure.count")
	reapedProcesses           = expvar.NewInt("process.reaped")
	processCount              = expvar.NewInt("process.count")
	threadCount               = expvar.NewInt("process.thread.count")
	moduleCount               = expvar.NewInt("process.module.count")
	mmapCount                 = expvar.NewInt("process.mmap.count")
	pebReadErrors             = expvar.NewInt("process.peb.read.errors")
)

type snapshotter struct {
	mu      sync.RWMutex
	procs   map[uint32]*pstypes.PS
	dirty   map[uint32]*pstypes.PS
	dmu     sync.RWMutex
	quit    chan struct{}
	config  *config.Config
	hsnap   handle.Snapshotter
	capture bool
}

// NewSnapshotter returns a new instance of the process snapshotter.
func NewSnapshotter(hsnap handle.Snapshotter, config *config.Config) Snapshotter {
	s := &snapshotter{
		procs:  make(map[uint32]*pstypes.PS),
		dirty:  make(map[uint32]*pstypes.PS),
		quit:   make(chan struct{}, 1),
		config: config,
		hsnap:  hsnap,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.hsnap.RegisterCreateCallback(s.onHandleCreated)
	s.hsnap.RegisterDestroyCallback(s.onHandleDestroyed)

	go s.gcDeadProcesses()

	return s
}

// NewSnapshotterFromKcap restores the snapshotter state from the kcap file.
func NewSnapshotterFromKcap(hsnap handle.Snapshotter, config *config.Config) Snapshotter {
	s := &snapshotter{
		procs:   make(map[uint32]*pstypes.PS),
		dirty:   make(map[uint32]*pstypes.PS),
		quit:    make(chan struct{}, 1),
		config:  config,
		hsnap:   hsnap,
		capture: true,
	}

	s.hsnap.RegisterCreateCallback(s.onHandleCreated)
	s.hsnap.RegisterDestroyCallback(s.onHandleDestroyed)

	return s
}

func (s *snapshotter) WriteFromKcap(e *kevent.Kevent) error {
	switch e.Type {
	case ktypes.CreateProcess, ktypes.ProcessRundown:
		s.mu.Lock()
		defer s.mu.Unlock()
		proc := e.PS
		if proc == nil {
			return nil
		}
		pid, err := e.Kparams.GetPid()
		if err != nil {
			return err
		}
		ppid, err := e.Kparams.GetPpid()
		if err != nil {
			return err
		}
		if proc.PID == proc.Ppid ||
			(e.IsProcessRundown() && pid == sys.InvalidProcessID) {
			return nil
		}
		if e.IsProcessRundown() {
			proc.Parent = s.procs[ppid]
		} else {
			proc, err = s.newProcState(pid, ppid, e)
			if err != nil {
				return err
			}
		}
		s.procs[pid] = proc
	case ktypes.CreateThread, ktypes.ThreadRundown:
		return s.AddThread(e)
	case ktypes.LoadImage, ktypes.ImageRundown:
		return s.AddModule(e)
	}
	return nil
}

func (s *snapshotter) Write(e *kevent.Kevent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	processCount.Add(1)
	pid, err := e.Kparams.GetPid()
	if err != nil {
		return err
	}
	ppid, err := e.Kparams.GetPpid()
	if err != nil {
		return err
	}
	proc, err := s.newProcState(pid, ppid, e)
	s.procs[pid] = proc
	// adjust the process which is generating
	// the event. For `CreateProcess` events
	// the process context is scoped to the
	// parent/creator process. Otherwise, it
	// is a regular rundown event that doesn't
	// require consulting the process in the
	// snapshot state
	if e.IsProcessRundown() {
		e.PS = proc
	} else {
		e.PS = s.procs[e.PID]
	}
	return err
}

func (s *snapshotter) AddThread(e *kevent.Kevent) error {
	pid, err := e.Kparams.GetPid()
	if err != nil {
		return err
	}
	threadCount.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	proc, ok := s.procs[pid]
	if !ok {
		return nil
	}
	thread := pstypes.Thread{}
	thread.Tid, _ = e.Kparams.GetTid()
	thread.UstackBase = e.Kparams.TryGetAddress(kparams.UstackBase)
	thread.UstackLimit = e.Kparams.TryGetAddress(kparams.UstackLimit)
	thread.KstackBase = e.Kparams.TryGetAddress(kparams.KstackBase)
	thread.KstackLimit = e.Kparams.TryGetAddress(kparams.KstackLimit)
	thread.IOPrio, _ = e.Kparams.GetUint8(kparams.IOPrio)
	thread.BasePrio, _ = e.Kparams.GetUint8(kparams.BasePrio)
	thread.PagePrio, _ = e.Kparams.GetUint8(kparams.PagePrio)
	thread.StartAddress = e.Kparams.TryGetAddress(kparams.StartAddress)
	proc.AddThread(thread)
	return nil
}

func (s *snapshotter) AddModule(e *kevent.Kevent) error {
	pid, err := e.Kparams.GetPid()
	if err != nil {
		return err
	}
	moduleCount.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if pid == 0 && e.IsImageRundown() {
		// assume system process if pid is zero
		pid = SystemPID
	}
	proc, ok := s.procs[pid]
	if !ok {
		return nil
	}
	module := pstypes.Module{}
	module.Size, _ = e.Kparams.GetUint64(kparams.ImageSize)
	module.Checksum, _ = e.Kparams.GetUint32(kparams.ImageCheckSum)
	module.Name = e.GetParamAsString(kparams.ImageFilename)
	module.BaseAddress = e.Kparams.TryGetAddress(kparams.ImageBase)
	module.DefaultBaseAddress = e.Kparams.TryGetAddress(kparams.ImageDefaultBase)
	module.SignatureLevel, _ = e.Kparams.GetUint32(kparams.ImageSignatureLevel)
	module.SignatureType, _ = e.Kparams.GetUint32(kparams.ImageSignatureType)
	if module.IsExecutable() && len(proc.Exe) < len(module.Name) {
		proc.Exe = module.Name
	}
	proc.AddModule(module)
	return nil
}

func (s *snapshotter) RemoveThread(pid uint32, tid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	proc, ok := s.procs[pid]
	if !ok {
		return nil
	}
	proc.RemoveThread(tid)
	threadCount.Add(-1)
	return nil
}

func (s *snapshotter) RemoveModule(pid uint32, module string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	proc, ok := s.procs[pid]
	if !ok {
		return nil
	}
	proc.RemoveModule(module)
	moduleCount.Add(-1)
	return nil
}

func (s *snapshotter) FindModule(addr va.Address) (bool, *pstypes.Module) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, proc := range s.procs {
		for _, mod := range proc.Modules {
			if mod.BaseAddress == addr {
				return true, &mod
			}
		}
	}
	return false, nil
}

func (s *snapshotter) AddFileMapping(e *kevent.Kevent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	proc, ok := s.procs[e.PID]
	if !ok {
		return nil
	}

	filename := e.GetParamAsString(kparams.FileName)
	ext := strings.ToLower(filepath.Ext(filename))
	// skip redundant or unneeded memory-mapped files
	if ext == ".dll" || ext == ".exe" || ext == ".mui" {
		return nil
	}
	mmapCount.Add(1)
	mmap := pstypes.Mmap{}
	mmap.File = filename
	mmap.BaseAddress = e.Kparams.TryGetAddress(kparams.FileViewBase)
	mmap.Size, _ = e.Kparams.GetUint64(kparams.FileViewSize)

	proc.MapFile(mmap)

	return nil
}

func (s *snapshotter) RemoveFileMapping(pid uint32, addr va.Address) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	proc, ok := s.procs[pid]
	if !ok {
		return nil
	}
	mmapCount.Add(-1)
	proc.UnmapFile(addr)
	return nil
}

func (s *snapshotter) Close() error {
	s.quit <- struct{}{}
	return nil
}

func (s *snapshotter) newProcState(pid, ppid uint32, e *kevent.Kevent) (*pstypes.PS, error) {
	proc := pstypes.New(
		pid,
		ppid,
		e.GetParamAsString(kparams.ProcessName),
		e.GetParamAsString(kparams.Cmdline),
		e.GetParamAsString(kparams.Exe),
		e.Kparams.MustGetSID(),
		e.Kparams.MustGetUint32(kparams.SessionID),
	)
	proc.Parent = s.procs[ppid]
	proc.StartTime, _ = e.Kparams.GetTime(kparams.StartTime)
	proc.IsWOW64 = (e.Kparams.MustGetUint32(kparams.ProcessFlags) & kevent.PsWOW64) != 0
	proc.IsPackaged = (e.Kparams.MustGetUint32(kparams.ProcessFlags) & kevent.PsPackaged) != 0
	proc.IsProtected = (e.Kparams.MustGetUint32(kparams.ProcessFlags) & kevent.PsProtected) != 0

	if !s.capture {
		if proc.Username != "" {
			e.AppendParam(kparams.Username, kparams.UnicodeString, proc.Username)
		}
		if proc.Domain != "" {
			e.AppendParam(kparams.Domain, kparams.UnicodeString, proc.Domain)
		}
		// retrieve process handles
		var err error
		proc.Handles, err = s.hsnap.FindHandles(pid)
		if err != nil {
			return proc, err
		}
	}

	// return early if we're reading from the capture file
	if s.capture {
		// reset username/domain from captured event parameters
		proc.Domain = e.GetParamAsString(kparams.Domain)
		proc.Username = e.GetParamAsString(kparams.Username)
		return proc, nil
	}

	// retrieve Portable Executable data
	var err error
	proc.PE, err = pe.ParseFileWithConfig(proc.Exe, s.config.PE)
	if err != nil {
		return proc, err
	}

	// try to read the PEB (Process Environment Block)
	// to access environment variables and the process
	// current working directory
	access := uint32(windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ)
	process, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		return proc, nil
	}
	//nolint:errcheck
	defer windows.CloseHandle(process)

	// read PEB
	peb, err := ReadPEB(process)
	if err != nil {
		pebReadErrors.Add(1)
		return proc, err
	}
	proc.Envs = peb.GetEnvs()
	proc.Cwd = peb.GetCurrentWorkingDirectory()

	return proc, nil
}

func (s *snapshotter) Remove(e *kevent.Kevent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid, err := e.Kparams.GetPid()
	if err != nil {
		return err
	}
	// remove process from primary map and
	// move to dirty map. This is required
	// to prevent dropping process state from
	// events when TerminateProcess event is
	// emitted before subsequent events
	if proc := s.procs[pid]; proc != nil {
		s.dmu.Lock()
		defer s.dmu.Unlock()
		s.dirty[pid] = proc
		// schedule removal
		remove := func(pid uint32) func() {
			return func() {
				s.dmu.Lock()
				defer s.dmu.Unlock()
				if ps, ok := s.dirty[pid]; ok {
					delete(s.dirty, pid)
					log.Debugf("dirty process removed: %s. Dirty procs: %d", ps.Name, len(s.dirty))
				}
			}
		}
		time.AfterFunc(time.Second*5, remove(pid))
	}
	delete(s.procs, pid)
	processCount.Add(-1)
	// reset parent if it died after spawning a process
	for procID, proc := range s.procs {
		if proc.Ppid == pid {
			s.procs[procID].Parent = nil
		}
	}
	return nil
}

func (s *snapshotter) Put(proc *pstypes.PS) {
	if proc != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.procs[proc.PID] = proc
	}
}

func (s *snapshotter) FindAndPut(pid uint32) *pstypes.PS {
	ok, proc := s.Find(pid)
	if !ok {
		s.Put(proc)
	}
	return proc
}

func (s *snapshotter) Find(pid uint32) (bool, *pstypes.PS) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ps, ok := s.procs[pid]
	if ok {
		return true, ps
	}
	if s.capture || pid == sys.InvalidProcessID {
		return false, nil
	}

	// check if the process is in dirty map
	s.dmu.RLock()
	defer s.dmu.RUnlock()
	if ps := s.dirty[pid]; ps != nil {
		return true, ps
	}

	processLookupFailureCount.Add(strconv.Itoa(int(pid)), 1)

	proc := &pstypes.PS{
		PID:     pid,
		Ppid:    sys.InvalidProcessID,
		Threads: make(map[uint32]pstypes.Thread),
		Modules: make([]pstypes.Module, 0),
		Handles: make([]htypes.Handle, 0),
	}

	getProcExecutable := func(process windows.Handle) (string, string) {
		var size uint32 = windows.MAX_PATH
		n := make([]uint16, size)
		err := windows.QueryFullProcessImageName(process, 0, &n[0], &size)
		if err != nil {
			return "", ""
		}
		return windows.UTF16ToString(n), filepath.Base(windows.UTF16ToString(n))
	}

	access := uint32(windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ)
	process, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		// the access to protected / system process can't be achieved
		// through `PROCESS_VM_READ` or `PROCESS_QUERY_INFORMATION` flags.
		// Try to acquire the process handle again but with restricted access
		// rights to be able to obtain other attributes such as the full process's
		// image executable path or process times
		process, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return false, nil
		}
	}
	//nolint:errcheck
	defer windows.CloseHandle(process)

	// get process executable full path and name
	proc.Exe, proc.Name = getProcExecutable(process)

	// consult process parent id
	info, err := sys.QueryInformationProcess[windows.PROCESS_BASIC_INFORMATION](process, windows.ProcessBasicInformation)
	if err != nil {
		return false, proc
	}
	proc.Ppid = uint32(info.InheritedFromUniqueProcessId)

	// retrieve Portable Executable data
	proc.PE, err = pe.ParseFileWithConfig(proc.Exe, s.config.PE)
	if err != nil {
		return false, proc
	}

	// get process times
	var (
		ct windows.Filetime
		xt windows.Filetime
		kt windows.Filetime
		ut windows.Filetime
	)
	err = windows.GetProcessTimes(process, &ct, &xt, &kt, &ut)
	if err != nil {
		return false, proc
	}
	proc.StartTime = time.Unix(0, ct.Nanoseconds())

	// get process token attributes
	var token windows.Token
	err = windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, proc
	}
	defer token.Close()
	usr, err := token.GetTokenUser()
	if err != nil {
		return false, proc
	}
	proc.SID = usr.User.Sid.String()
	proc.Username, proc.Domain, _, _ = usr.User.Sid.LookupAccount("")

	// retrieve process handles
	proc.Handles, err = s.hsnap.FindHandles(pid)
	if err != nil {
		return false, proc
	}

	// read PEB
	peb, err := ReadPEB(process)
	if err != nil {
		pebReadErrors.Add(1)
		return false, proc
	}
	proc.Envs = peb.GetEnvs()
	proc.Cmdline = peb.GetCommandLine()
	proc.SessionID = peb.GetSessionID()
	proc.Cwd = peb.GetCurrentWorkingDirectory()

	// get process creation attributes
	var isWOW64 bool
	if err := windows.IsWow64Process(process, &isWOW64); err != nil && isWOW64 {
		proc.IsWOW64 = true
	}
	if p, err := sys.QueryInformationProcess[sys.PsProtection](process, sys.ProcessProtectionInformation); err != nil && p != nil {
		proc.IsProtected = p.IsProtected()
	}
	proc.IsPackaged = sys.IsProcessPackaged(process)

	return false, proc
}

func (s *snapshotter) Size() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint32(len(s.procs))
}

// gcDeadProcesses periodically scans the map of the snapshot's processes and removes
// any terminated processes from it. This guarantees that any leftovers are cleaned-up
// in case we miss process' terminate events.
func (s *snapshotter) gcDeadProcesses() {
	tick := time.NewTicker(reapPeriod)
	for {
		select {
		case <-tick.C:
			s.mu.Lock()
			ss := len(s.procs)
			log.Debugf("scanning for dead processes on the snapshot of %d items", ss)

			for pid := range s.procs {
				proc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
				if err != nil {
					continue
				}
				if !sys.IsProcessRunning(proc) {
					delete(s.procs, pid)
				}
				_ = windows.CloseHandle(proc)
			}

			if ss > len(s.procs) {
				reaped := ss - len(s.procs)
				reapedProcesses.Add(int64(reaped))
				log.Debugf("%d dead process(es) reaped", reaped)
			}
			s.mu.Unlock()
		case <-s.quit:
			tick.Stop()
		}
	}
}

func (s *snapshotter) onHandleCreated(pid uint32, handle htypes.Handle) {
	s.mu.RLock()
	ps, ok := s.procs[pid]
	s.mu.RUnlock()
	if ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		ps.AddHandle(handle)
		s.procs[pid] = ps
	}
}

func (s *snapshotter) onHandleDestroyed(pid uint32, rawHandle windows.Handle) {
	s.mu.RLock()
	ps, ok := s.procs[pid]
	s.mu.RUnlock()
	if ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		ps.RemoveHandle(rawHandle)
		s.procs[pid] = ps
	}
}
