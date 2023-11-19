//go:build windows
// +build windows

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

package handle

import (
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"golang.org/x/sys/windows"
	"os"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/config"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	log "github.com/sirupsen/logrus"
)

var (
	globalBufferSize uint32 = 4096

	handleNameQueryFailures = expvar.NewMap("handle.name.query.failures")
	handleSnapshotCount     = expvar.NewInt("handle.snapshot.count")
	handleSnapshotBytes     = expvar.NewInt("handle.snapshot.bytes")
)

const (
	// maxProcHandles determines the maximum number of handles the handle snapshotter can store
	maxProcHandles = 70000
	// maxHandlesPerProc determines the maximum number of handles a particular process state can store
	maxHandlesPerProc = 800
)

// CreateCallback defines the function that is triggered when new handle is conceived
type CreateCallback func(pid uint32, handle htypes.Handle)

// DestroyCallback defines the function signature that is fired upon handle's destruction
type DestroyCallback func(pid uint32, rawHandle windows.Handle)

// SnapshotBuildCompleted is the function type for snapshot completed signal
type SnapshotBuildCompleted func(total uint64, named uint64)

// Snapshotter keeps the system-wide snapshot of allocated handles always when handle kernel events are enabled or
// supported on the target system. It also provides facilities for obtaining a list of handles pertaining to the specific
// process.
type Snapshotter interface {
	// Write updates the snapshotter state by storing a new entry for the inbound create handle event. It also notifies
	// the registered callback that a new handle has been created.
	Write(kevt *kevent.Kevent) error
	// Remove destroys the handle state for the specified handle object. The removal callback is triggered when an item
	// is deleted from the store.
	Remove(kevt *kevent.Kevent) error
	// FindHandles returns a list of all known handles for the specified process identifier.
	FindHandles(pid uint32) ([]htypes.Handle, error)
	// FindByObject returns the handle for the given handle object reference.
	FindByObject(object uint64) (htypes.Handle, bool)
	// RegisterCreateCallback registers a function that's triggered when new handle is created.
	RegisterCreateCallback(fn CreateCallback)
	// RegisterDestroyCallback registers a function that's called when existing handle is disposed.
	RegisterDestroyCallback(fn DestroyCallback)
	// GetSnapshot returns all the handles present in the snapshotter state.
	GetSnapshot() []htypes.Handle
	// Close closes snapshotter and disposes all allocated resources.
	Close() error
}

type snapshotter struct {
	mu                     sync.Mutex
	handlesByObject        map[uint64]htypes.Handle
	hc                     chan htypes.Handle
	hdone                  chan struct{}
	config                 *config.Config
	snapshotBuildCompleted SnapshotBuildCompleted
	createCallback         CreateCallback
	destroyCallback        DestroyCallback
	housekeepTick          *time.Ticker
	initSnap               bool
	capture                bool
}

// NewSnapshotter constructs a new instance of the handle snapshotter. If `SnapshotBuildCompleted` function is provided
// it will receive the total number of discovered handles as well as the count of the non-nameless handles.
func NewSnapshotter(config *config.Config, fn SnapshotBuildCompleted) Snapshotter {
	s := &snapshotter{
		hc:                     make(chan htypes.Handle),
		hdone:                  make(chan struct{}, 1),
		handlesByObject:        make(map[uint64]htypes.Handle),
		snapshotBuildCompleted: fn,
		config:                 config,
		housekeepTick:          time.NewTicker(time.Minute),
		initSnap:               config.InitHandleSnapshot,
	}

	if s.initSnap {
		go s.consumeHandles()
		go s.initSnapshot()
		go s.housekeeping()
	} else {
		if fn != nil {
			fn(0, 0)
		}
	}

	return s
}

// NewFromKcap builds the handle snapshotter from kcap state.
func NewFromKcap(handles []htypes.Handle) Snapshotter {
	s := &snapshotter{
		handlesByObject: make(map[uint64]htypes.Handle),
		capture:         true,
	}
	for _, handle := range handles {
		s.handlesByObject[handle.Object] = handle
	}
	return s
}

func (s *snapshotter) FindByObject(object uint64) (htypes.Handle, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.handlesByObject[object]; ok {
		return h, ok
	}
	return htypes.Handle{}, false
}

func (s *snapshotter) FindHandles(pid uint32) ([]htypes.Handle, error) {
	if !s.config.EnumerateHandles {
		return []htypes.Handle{}, nil
	}
	if pid == uint32(os.Getpid()) || pid == 0 { // ignore current, idle processes
		return []htypes.Handle{}, nil
	}
	if s.capture {
		handles := make([]htypes.Handle, 0)
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, h := range s.handlesByObject {
			if h.Pid == pid {
				handles = append(handles, h)
			}
		}
		return handles, nil
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		// trying to obtain the handle with `PROCESS_QUERY_INFORMATION` access on a protected
		// process will always fail, so our best effort is to collect handles for those
		// processes in the snapshot's state
		handles := make([]htypes.Handle, 0)
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, h := range s.handlesByObject {
			if h.Pid == pid && h.Type != "" {
				handles = append(handles, h)
			}
		}
		return handles, nil
	}
	//nolint:errcheck
	defer windows.CloseHandle(process)

	snapshot, err := sys.QueryInformationProcess[sys.ProcessHandleSnapshotInformation](process, windows.ProcessHandleInformation)
	if err != nil {
		if err.Error() == "An attempt was made to access an exiting process." {
			return nil, nil
		}
		return nil, fmt.Errorf("unable to query handles for process id %d: %v", pid, err)
	}

	// enumerate process's handles and try to resolve
	// the type and the name of each allocated handle
	handles := make([]htypes.Handle, 0)
	count := snapshot.NumberOfHandles
	if count > maxHandlesPerProc {
		log.Warnf("maximum handle table size reached for %d pid. "+
			"Shrinking table size from %d to %d handles", pid, count, maxHandlesPerProc)
		count = maxHandlesPerProc
	}
	sysHandles := (*[1 << 30]sys.ProcessHandleTableEntryInfo)(unsafe.Pointer(&snapshot.Handles[0]))[:count:count]

	for _, sysHandle := range sysHandles {
		h, err := s.getHandle(sysHandle.Handle, 0, uint16(sysHandle.ObjectTypeIndex), pid, false)
		if err != nil {
			continue
		}
		// ignore file handles since we can't get the
		// file name. Also, only collect named handles
		if h.Type == File && h.Name == "" {
			continue
		}
		handles = append(handles, h)
	}
	return handles, nil
}

// initSnapshot builds the initial snapshot state by enumerating system-wide handles.
func (s *snapshotter) initSnapshot() {
	size := globalBufferSize
	buf := make([]byte, size)
	for {
		err := windows.NtQuerySystemInformation(windows.SystemExtendedHandleInformation, unsafe.Pointer(&buf[0]), size, nil)
		if err == windows.STATUS_INFO_LENGTH_MISMATCH || err == windows.STATUS_BUFFER_TOO_SMALL || err == windows.STATUS_BUFFER_OVERFLOW {
			size *= 2
			buf = make([]byte, size)
		} else if err == nil {
			sysHandleInfo := (*sys.SystemHandleInformationEx)(unsafe.Pointer(&buf[0]))
			count := int(sysHandleInfo.NumberOfHandles)
			if count > maxProcHandles {
				log.Warnf("handle snapshotter size exceeded. Shrinking from %d to %d handles", count, maxProcHandles)
				count = maxProcHandles
			}
			sysHandles := (*[1 << 30]sys.SystemHandleTableEntryInfoEx)(unsafe.Pointer(&sysHandleInfo.Handles[0]))[:count:count]

			// iterate through available handles to get extended info
			// and send handle structure instances to the channel
			for _, sysHandle := range sysHandles {
				pid := sysHandle.ProcessID
				if pid == uintptr(os.Getpid()) {
					continue
				}
				handle, err := s.getHandle(sysHandle.Handle, sysHandle.Object, sysHandle.ObjectTypeIndex, uint32(pid), true)
				if err != nil || handle.Type == "" {
					continue
				}
				s.hc <- handle
			}
			s.hdone <- struct{}{}
			break
		} else {
			log.Warnf("couldn't enumerate system-wide handles: %v", err)
			break
		}
	}
}

func (s *snapshotter) getHandle(rawHandle windows.Handle, obj uint64, typeIndex uint16, pid uint32, withTimeout bool) (htypes.Handle, error) {
	typ := htypes.ConvertTypeIDToName(typeIndex)
	if typ == "" {
		dup, err := Duplicate(rawHandle, pid, windows.GENERIC_ALL)
		if err != nil {
			return htypes.Handle{Num: rawHandle, Object: obj}, nil
		}
		typ, err = QueryObjectType(dup)
		if err != nil {
			return htypes.Handle{Num: rawHandle, Object: obj}, nil
		}
	}
	handle := htypes.Handle{
		Num:    rawHandle,
		Object: obj,
		Type:   typ,
		Pid:    pid,
	}
	// IoCompletion handles shouldn't be duplicated
	if handle.Type == IoCompletion {
		return handle, nil
	}
	// use the required duplicate access to query handle name
	var dupAccess uint32
	switch typ {
	case ALPCPort:
		dupAccess = windows.READ_CONTROL
	case Process:
		dupAccess = windows.PROCESS_QUERY_INFORMATION
	case Mutant:
		dupAccess = windows.SEMAPHORE_ALL_ACCESS
	}
	dup, err := Duplicate(rawHandle, pid, dupAccess)
	if err != nil {
		return handle, err
	}
	//nolint:errcheck
	defer windows.CloseHandle(dup)
	handle.Name, handle.MD, err = QueryName(dup, typ, withTimeout)
	if err != nil {
		// even though we weren't able to query handle name we still
		// return handle info with handle type and other metadata
		handleNameQueryFailures.Add(strconv.Itoa(int(pid)), 1)
		return handle, nil
	}
	return handle, nil
}

func (s *snapshotter) consumeHandles() {
	for {
		select {
		case h := <-s.hc:
			s.mu.Lock()
			handleSnapshotCount.Add(1)
			handleSnapshotBytes.Add(int64(h.Len()))
			s.handlesByObject[h.Object] = h
			s.mu.Unlock()
		case <-s.hdone:
			log.Debug("initial handle enumeration has finalized")
			s.mu.Lock()
			var named uint64
			for _, h := range s.handlesByObject {
				if h.Name != "" {
					named++
				}
				if s.createCallback != nil && h.Type == File {
					// for safety reasons related to deadlocks we are skipping file handles
					// for Rundown/Create process events, we'll send these handles after initial
					// system-wide scan has completed
					if h.Name != "" {
						s.createCallback(h.Pid, h)
					}
				}
			}
			s.mu.Unlock()
			if s.snapshotBuildCompleted != nil {
				s.snapshotBuildCompleted(uint64(len(s.handlesByObject)), named)
			}
			return
		}
	}
}

func (s *snapshotter) housekeeping() {
	for {
		<-s.housekeepTick.C

		size := globalBufferSize
		buf := make([]byte, size)
	loop:
		for {
			err := windows.NtQuerySystemInformation(windows.SystemExtendedHandleInformation, unsafe.Pointer(&buf[0]), size, nil)
			if err == windows.STATUS_INFO_LENGTH_MISMATCH || err == windows.STATUS_BUFFER_TOO_SMALL || err == windows.STATUS_BUFFER_OVERFLOW {
				size *= 2
				buf = make([]byte, size)
			} else if err == nil {
				sysHandleInfo := (*sys.SystemHandleInformationEx)(unsafe.Pointer(&buf[0]))
				count := int(sysHandleInfo.NumberOfHandles)
				if count > maxProcHandles {
					log.Warnf("handle snapshotter size exceeded. Shrinking from %d to %d handles", count, maxProcHandles)
					count = maxProcHandles
				}
				sysHandles := (*[1 << 30]sys.SystemHandleTableEntryInfoEx)(unsafe.Pointer(&sysHandleInfo.Handles[0]))[:count:count]

				s.mu.Lock()
				for _, sysHandle := range sysHandles {
					if handle, ok := s.handlesByObject[sysHandle.Object]; !ok {
						handleSnapshotCount.Add(-1)
						handleSnapshotBytes.Add(-int64(handle.Len()))
						delete(s.handlesByObject, sysHandle.Object)
					}
				}
				s.mu.Unlock()

				break loop
			} else {
				log.Warnf("couldn't get system-wide handles in housekeeping timer: %v", err)
				break loop
			}
		}
	}
}

func (s *snapshotter) RegisterCreateCallback(fn CreateCallback) {
	s.createCallback = fn
}

func (s *snapshotter) RegisterDestroyCallback(fn DestroyCallback) {
	s.destroyCallback = fn
}

func (s *snapshotter) GetSnapshot() []htypes.Handle {
	handles := make([]htypes.Handle, 0, len(s.handlesByObject))
	for _, h := range s.handlesByObject {
		handles = append(handles, h)
	}
	return handles
}

func (s *snapshotter) Write(e *kevent.Kevent) error {
	if !e.IsCreateHandle() {
		return fmt.Errorf("expected CreateHandle event but got %s", e.Type)
	}
	h := unwrapHandle(e)
	obj, err := e.Kparams.GetUint64(kparams.HandleObject)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.handlesByObject[obj] = h
	s.mu.Unlock()
	return nil
}

func (s *snapshotter) Remove(e *kevent.Kevent) error {
	if !e.IsCloseHandle() {
		return fmt.Errorf("expected CloseHandle event but got %s", e.Type)
	}
	obj, err := e.Kparams.GetUint64(kparams.HandleObject)
	if err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.handlesByObject, obj)
	s.mu.Unlock()
	return nil
}

func (s *snapshotter) Close() error {
	if s.housekeepTick != nil {
		s.housekeepTick.Stop()
	}
	return nil
}

func unwrapHandle(e *kevent.Kevent) htypes.Handle {
	h := htypes.Handle{}
	h.Type = e.GetParamAsString(kparams.HandleObjectTypeID)
	h.Object, _ = e.Kparams.GetUint64(kparams.HandleObject)
	h.Name, _ = e.Kparams.GetString(kparams.HandleObjectName)
	return h
}
