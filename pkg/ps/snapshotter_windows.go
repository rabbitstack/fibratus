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
	"os"
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
	hndl "github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/syscall/process"
	"github.com/rabbitstack/fibratus/pkg/syscall/winerrno"
	log "github.com/sirupsen/logrus"
)

var (
	// reapPeriod specifies the interval for triggering the house keeping of dead processes
	reapPeriod = time.Minute * 2

	processLookupFailureCount = expvar.NewMap("process.lookup.failure.count")
	reapedProcesses           = expvar.NewInt("process.reaped")
	processCount              = expvar.NewInt("process.count")
	threadCount               = expvar.NewInt("process.thread.count")
	moduleCount               = expvar.NewInt("process.module.count")
	pebReadErrors             = expvar.NewInt("process.peb.read.errors")
)

type snapshotter struct {
	mu         sync.RWMutex
	procs      map[uint32]*pstypes.PS
	quit       chan struct{}
	config     *config.Config
	handleSnap handle.Snapshotter
	peReader   pe.Reader
	capture    bool
}

// NewSnapshotter returns a new instance of the process snapshotter.
func NewSnapshotter(handleSnap handle.Snapshotter, config *config.Config) Snapshotter {
	s := &snapshotter{
		procs:      make(map[uint32]*pstypes.PS),
		quit:       make(chan struct{}),
		config:     config,
		handleSnap: handleSnap,
		peReader:   pe.NewReader(config.PE),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.handleSnap.RegisterCreateCallback(s.onHandleCreated)
	s.handleSnap.RegisterDestroyCallback(s.onHandleDestroyed)

	go s.gcDeadProcesses()

	return s
}

// NewSnapshotterFromKcap restores the snapshotter state from the kcap file.
func NewSnapshotterFromKcap(handleSnap handle.Snapshotter, config *config.Config) Snapshotter {
	s := &snapshotter{
		procs:      make(map[uint32]*pstypes.PS),
		quit:       make(chan struct{}),
		config:     config,
		handleSnap: handleSnap,
		peReader:   pe.NewReader(config.PE),
		capture:    true,
	}

	s.handleSnap.RegisterCreateCallback(s.onHandleCreated)
	s.handleSnap.RegisterDestroyCallback(s.onHandleDestroyed)

	return s
}

func (s *snapshotter) WriteFromKcap(kevt *kevent.Kevent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch kevt.Type {
	case ktypes.CreateProcess, ktypes.ProcessRundown:
		ps := kevt.PS
		if ps == nil {
			return nil
		}
		pid, err := kevt.Kparams.GetPid()
		if err != nil {
			return err
		}
		if kevt.Type == ktypes.ProcessRundown {
			// invalid process
			if ps.PID == ps.Ppid {
				return nil
			}
			s.procs[pid] = ps
		} else {
			s.procs[pid] = pstypes.FromKevent(unwrapParams(pid, kevt))
		}
		ppid, err := kevt.Kparams.GetPpid()
		if err != nil {
			return err
		}
		ps.Parent = s.procs[ppid]
	case ktypes.CreateThread, ktypes.ThreadRundown:
		pid, err := kevt.Kparams.GetPid()
		if err != nil {
			return err
		}
		threadCount.Add(1)
		thread := pstypes.ThreadFromKevent(unwrapThreadParams(pid, kevt))
		if ps, ok := s.procs[pid]; ok {
			ps.AddThread(thread)
			ps.Parent = s.procs[ps.Ppid]
		}
	case ktypes.LoadImage, ktypes.ImageRundown:
		pid, err := kevt.Kparams.GetPid()
		if err != nil {
			return err
		}
		moduleCount.Add(1)
		ps, ok := s.procs[pid]
		if !ok {
			return nil
		}
		ps.AddModule(pstypes.ImageFromKevent(unwrapImageParams(kevt)))
	}
	return nil
}

func (s *snapshotter) Write(kevt *kevent.Kevent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch kevt.Type {
	case ktypes.CreateProcess, ktypes.ProcessRundown:
		pid, err := kevt.Kparams.GetPid()
		if err != nil {
			return err
		}
		// discard writing the snapshot state if the pid is
		// already present. This usually happens when we alter
		// the tracing session to induce the arrival of rundown events
		// by calling into the `etw.SetTraceInformation` Windows API
		// function twice in a row.
		// For more pointers check `kstream/controller_windows.go`
		// and the `etw.SetTraceInformation` API function
		if _, ok := s.procs[pid]; ok {
			return nil
		}
		processCount.Add(1)

		// ETW can sometimes report invalid process id, so we try
		// to obtain the process id from its thread identifier
		if kevt.Type == ktypes.CreateProcess && pid == winerrno.InvalidPID {
			pid = pidFromThreadID(kevt.Tid)
		}

		ps := pstypes.FromKevent(unwrapParams(pid, kevt))

		// enumerate process handles
		ps.Handles, err = s.handleSnap.FindHandles(pid)
		if err != nil {
			log.Warnf("couldn't enumerate handles for pid (%d): %v", pid, err)
		}
		ps.Parent = s.procs[ps.Ppid]

		// inspect PE metadata and attach corresponding headers
		s.readPE(ps)

		// adjust the process that is producing the event. For
		// `CreateProcess` events the process context is scoped
		// to the parent/creator process. Otherwise, it is a regular
		// enumeration event that doesn't require consulting the
		// process in the snapshot state
		if kevt.Type == ktypes.CreateProcess {
			kevt.PS = s.procs[kevt.PID]
		} else {
			kevt.PS = ps
		}
		// try to enum process's env variables and the cwd
		flags := process.QueryInformation | process.VMRead
		h, err := process.Open(flags, false, pid)
		if err != nil {
			s.procs[pid] = ps
			return nil
		}
		defer h.Close()

		peb, err := ReadPEB(h)
		if err != nil {
			pebReadErrors.Add(1)
			s.procs[pid] = ps
			return nil
		}

		ps.Envs = peb.GetEnvs()
		ps.Cwd = peb.GetCurrentWorkingDirectory()

		if kevt.Type != ktypes.CreateProcess {
			kevt.PS = ps
		}

		s.procs[pid] = ps
	case ktypes.CreateThread, ktypes.ThreadRundown:
		pid, err := kevt.Kparams.GetPid()
		if err != nil {
			return err
		}
		threadCount.Add(1)
		if pid == winerrno.InvalidPID {
			threadID, _ := kevt.Kparams.GetTid()
			pid = pidFromThreadID(threadID)
		}
		// thread can be associated with the process
		// as it already exists in the map
		thread := pstypes.ThreadFromKevent(unwrapThreadParams(pid, kevt))
		if ps, ok := s.procs[pid]; ok {
			// append additional params
			kevt.Kparams.Append(kparams.Exe, kparams.UnicodeString, ps.Exe)
			ps.AddThread(thread)
			return nil
		}

		// search for missing process and attempt to get its info
		ps := s.findProcess(pid, thread)

		// enumerate process handles
		ps.Handles, err = s.handleSnap.FindHandles(pid)
		if err != nil {
			log.Warnf("couldn't enumerate handles for pid (%d): %v", pid, err)
		}
		ps.Parent = s.procs[ps.Ppid]

		s.procs[pid] = ps
	case ktypes.LoadImage, ktypes.ImageRundown:
		pid, err := kevt.Kparams.GetPid()
		if err != nil {
			return err
		}
		moduleCount.Add(1)
		ps, ok := s.procs[pid]
		if !ok {
			return nil
		}
		ps.AddModule(pstypes.ImageFromKevent(unwrapImageParams(kevt)))
	}
	return nil
}

func (s *snapshotter) Close() error {
	s.quit <- struct{}{}
	return nil
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
				h, err := process.Open(process.QueryLimitedInformation, false, pid)
				if err != nil {
					continue
				}
				if !process.IsAlive(h) {
					delete(s.procs, pid)
				}
				h.Close()
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

func pidFromThreadID(tid uint32) uint32 {
	pid, err := process.GetPIDFromThread(tid)
	if err != nil {
		return winerrno.InvalidPID
	}
	return pid
}

func ntoskrnl() string { return filepath.Join(os.Getenv("SystemRoot"), "ntoskrnl.exe") }

func fromPEB(pid, ppid uint32, peb *PEB, thread pstypes.Thread) *pstypes.PS {
	return pstypes.NewPS(
		pid,
		ppid,
		peb.GetImage(),
		peb.GetCurrentWorkingDirectory(),
		peb.GetCommandLine(),
		thread,
		peb.GetEnvs(),
	)
}

func (s *snapshotter) findProcess(pid uint32, thread pstypes.Thread) *pstypes.PS {
	// several system protected processes don't allow for getting their handles
	// even if SeDebugPrivilege is present in the process' token, so we'll handle
	// them manually
	switch pid {
	case 0:
		return pstypes.NewPS(pid, pid, "idle", "", "idle", thread, nil)
	case 4:
		return pstypes.NewPS(pid, 0, "System", "", ntoskrnl(), thread, nil)
	}
	flags := process.QueryInformation | process.VMRead
	h, err := process.Open(flags, false, pid)
	if err != nil {
		// the access to protected / system process can't be achieved through
		// `VMRead` or `QueryInformation` flags.
		// Try to acquire the process handle again but with restricted access rights,
		// so we can get the process image file name
		h, err = process.Open(
			process.QueryLimitedInformation,
			false,
			pid,
		)
		if err != nil {
			return pstypes.NewPS(pid, pid, "", "", "", thread, nil)
		}
	}
	defer h.Close()

	// read process's metadata from the PEB
	peb, err := ReadPEB(h)
	if err != nil {
		pebReadErrors.Add(1)
		// couldn't query process basic info or read the PEB,
		// so at least try to obtain the full process's image name
		image, err := process.QueryFullImageName(h)
		if err != nil {
			return pstypes.NewPS(pid, pid, "", "", "", thread, nil)
		}
		return pstypes.NewPS(pid, pid, image, "", image, thread, nil)
	}
	return fromPEB(pid, process.GetParentPID(h), peb, thread)
}

func (s *snapshotter) readPE(ps *pstypes.PS) {
	// skip imageless processes such as Idle, System or Registry
	pid := ps.PID
	if pid == 0 || pid == 4 || pid == 72 || pid == 128 {
		return
	}
	p, err := s.peReader.Read(ps.Exe)
	if err != nil {
		log.Warnf("fail to inspect PE metadata for process %s (%d): %v", ps.Name, ps.PID, err)
		return
	}

	if p == nil {
		return
	}

	ps.PE = p
	s.procs[pid] = ps
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

func (s *snapshotter) onHandleDestroyed(pid uint32, num hndl.Handle) {
	s.mu.RLock()
	ps, ok := s.procs[pid]
	s.mu.RUnlock()
	if ok {
		s.mu.Lock()
		defer s.mu.Unlock()
		ps.RemoveHandle(num)
		s.procs[pid] = ps
	}
}

func (s *snapshotter) Remove(kevt *kevent.Kevent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pid, err := kevt.Kparams.GetPid()
	if err != nil {
		return err
	}
	switch kevt.Type {
	case ktypes.TerminateProcess:
		if _, ok := s.procs[pid]; ok {
			delete(s.procs, pid)
			processCount.Add(-1)
			return nil
		}
	case ktypes.TerminateThread:
		if ps, ok := s.procs[pid]; ok {
			tid, err := kevt.Kparams.GetTid()
			if err != nil {
				return err
			}
			ps.RemoveThread(tid)
			threadCount.Add(-1)
		}
	case ktypes.UnloadImage:
		pid, err := kevt.Kparams.GetPid()
		if err != nil {
			return err
		}
		if ps, ok := s.procs[pid]; ok {
			name, _ := kevt.Kparams.GetString(kparams.ImageFilename)
			ps.RemoveModule(name)
			moduleCount.Add(-1)
		}
	}
	return nil
}

func (s *snapshotter) Find(pid uint32) *pstypes.PS {
	s.mu.RLock()
	ps, ok := s.procs[pid]
	s.mu.RUnlock()
	if ok {
		return ps
	}
	if s.capture {
		return nil
	}
	processLookupFailureCount.Add(strconv.Itoa(int(pid)), 1)

	// allocate missing process's state and fill in metadata/handles
	thread := pstypes.Thread{}
	ps = s.findProcess(pid, thread)

	s.readPE(ps)

	// enumerate process handles
	var err error
	ps.Handles, err = s.handleSnap.FindHandles(pid)
	if err != nil {
		log.Warnf("couldn't enumerate handles for pid (%d): %v", pid, err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.procs[pid] = ps

	return ps
}

func (s *snapshotter) Size() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint32(len(s.procs))
}

func unwrapParams(pid uint32, kevt *kevent.Kevent) (uint32, uint32, string, string, string, string, uint8) {
	ppid, _ := kevt.Kparams.GetPpid()
	name, _ := kevt.Kparams.GetString(kparams.ProcessName)
	comm, _ := kevt.Kparams.GetString(kparams.Cmdline)
	exe, _ := kevt.Kparams.GetString(kparams.Exe)
	sid, _ := kevt.Kparams.GetString(kparams.UserSID)
	sessionID, _ := kevt.Kparams.GetUint32(kparams.SessionID)

	return pid, ppid, name, comm, exe, sid, uint8(sessionID)
}

func unwrapThreadParams(pid uint32, kevt *kevent.Kevent) (uint32, uint32, kparams.Hex, kparams.Hex, kparams.Hex, kparams.Hex, uint8, uint8, uint8, kparams.Hex) {
	tid, _ := kevt.Kparams.GetTid()
	ustackBase, _ := kevt.Kparams.GetHex(kparams.UstackBase)
	ustackLimit, _ := kevt.Kparams.GetHex(kparams.UstackLimit)
	kstackBase, _ := kevt.Kparams.GetHex(kparams.KstackBase)
	kstackLimit, _ := kevt.Kparams.GetHex(kparams.KstackLimit)
	ioPrio, _ := kevt.Kparams.GetUint8(kparams.IOPrio)
	basePrio, _ := kevt.Kparams.GetUint8(kparams.BasePrio)
	pagePrio, _ := kevt.Kparams.GetUint8(kparams.PagePrio)
	entrypoint, _ := kevt.Kparams.GetHex(kparams.StartAddr)

	return pid, tid, ustackBase, ustackLimit, kstackBase, kstackLimit, ioPrio, basePrio, pagePrio, entrypoint
}

func unwrapImageParams(kevt *kevent.Kevent) (uint32, uint32, string, kparams.Hex, kparams.Hex) {
	size, _ := kevt.Kparams.GetUint32(kparams.ImageSize)
	checksum, _ := kevt.Kparams.GetUint32(kparams.ImageCheckSum)
	name, _ := kevt.Kparams.GetString(kparams.ImageFilename)
	baseAddress, _ := kevt.Kparams.GetHex(kparams.ImageBase)
	defaultBaseAddress, _ := kevt.Kparams.GetHex(kparams.ImageDefaultBase)

	return size, checksum, name, baseAddress, defaultBaseAddress
}
