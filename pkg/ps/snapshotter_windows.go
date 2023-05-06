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
	"golang.org/x/sys/windows"
	"path/filepath"
	"strconv"
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

var (
	// reapPeriod specifies the interval for triggering the housekeeping of dead processes
	reapPeriod = time.Minute * 2

	processLookupFailureCount = expvar.NewMap("process.lookup.failure.count")
	reapedProcesses           = expvar.NewInt("process.reaped")
	processCount              = expvar.NewInt("process.count")
	threadCount               = expvar.NewInt("process.thread.count")
	moduleCount               = expvar.NewInt("process.module.count")
	pebReadErrors             = expvar.NewInt("process.peb.read.errors")
)

type snapshotter struct {
	mu      sync.RWMutex
	procs   map[uint32]*pstypes.PS
	quit    chan struct{}
	config  *config.Config
	hsnap   handle.Snapshotter
	capture bool
}

// NewSnapshotter returns a new instance of the process snapshotter.
func NewSnapshotter(hsnap handle.Snapshotter, config *config.Config) Snapshotter {
	s := &snapshotter{
		procs:  make(map[uint32]*pstypes.PS),
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
		proc.Parent = s.procs[ppid]
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
	thread.UstackBase, _ = e.Kparams.GetHex(kparams.UstackBase)
	thread.UstackLimit, _ = e.Kparams.GetHex(kparams.UstackLimit)
	thread.KstackBase, _ = e.Kparams.GetHex(kparams.KstackBase)
	thread.KstackLimit, _ = e.Kparams.GetHex(kparams.KstackLimit)
	thread.IOPrio, _ = e.Kparams.GetUint8(kparams.IOPrio)
	thread.BasePrio, _ = e.Kparams.GetUint8(kparams.BasePrio)
	thread.PagePrio, _ = e.Kparams.GetUint8(kparams.PagePrio)
	thread.Entrypoint, _ = e.Kparams.GetHex(kparams.StartAddr)
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
	proc, ok := s.procs[pid]
	if !ok {
		return nil
	}
	module := pstypes.Module{}
	module.Size, _ = e.Kparams.GetUint64(kparams.ImageSize)
	module.Checksum, _ = e.Kparams.GetUint32(kparams.ImageCheckSum)
	module.Name = e.GetParamAsString(kparams.ImageFilename)
	module.BaseAddress, _ = e.Kparams.GetHex(kparams.ImageBase)
	module.DefaultBaseAddress, _ = e.Kparams.GetHex(kparams.ImageDefaultBase)
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

	// retrieve Portable Executable data
	var err error
	proc.PE, err = pe.ParseFileWithConfig(proc.Exe, s.config.PE)
	if err != nil {
		return proc, err
	}

	// retrieve process handles
	proc.Handles, err = s.hsnap.FindHandles(pid)
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
			return false, proc
		}
	}
	defer windows.CloseHandle(process)

	// get process executable full path and name
	proc.Exe, proc.Name = getProcExecutable(process)

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

	// consult process parent id
	info, err := sys.QueryInformationProcess[windows.PROCESS_BASIC_INFORMATION](process, windows.ProcessBasicInformation)
	if err != nil {
		return false, proc
	}
	proc.Ppid = uint32(info.InheritedFromUniqueProcessId)

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
