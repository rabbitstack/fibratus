//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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
	"sync"

	"github.com/rabbitstack/fibratus/pkg/event"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// Snapshotter stores Linux process state for enrichment and rule evaluation.
type Snapshotter interface {
	// Write appends or updates process state from an inbound event.
	Write(*event.Event) error
	// Remove deletes process state for the event process identifier.
	Remove(*event.Event) error
	// Find attempts to retrieve process state for the specified process identifier.
	Find(pid uint64) (bool, *pstypes.PS)
	// FindAndPut retrieves process state. Procfs fallback enrichment will be added
	// when Linux capture is wired.
	FindAndPut(pid uint64) *pstypes.PS
	// Put inserts the process state into the snapshotter.
	Put(*pstypes.PS)
	// Size returns the total number of process state items.
	Size() uint32
	// Close closes the process snapshotter and disposes allocated resources.
	Close() error
	// AddThread builds thread state from the event representation.
	AddThread(*event.Event) error
	// RemoveThread removes the thread from the given process.
	RemoveThread(pid uint64, tid uint64) error
	// AddMmap adds a memory mapping to the process state.
	AddMmap(*event.Event) error
	// RemoveMmap removes a memory mapping at the given base address.
	RemoveMmap(pid uint64, addr va.Address) error
}

type snapshotter struct {
	mu    sync.RWMutex
	procs map[uint64]*pstypes.PS
}

// NewSnapshotter builds an in-memory Linux process snapshotter.
func NewSnapshotter() Snapshotter {
	return &snapshotter{procs: make(map[uint64]*pstypes.PS)}
}

func (s *snapshotter) Find(pid uint64) (bool, *pstypes.PS) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ps, ok := s.procs[pid]
	return ok, ps
}

func (s *snapshotter) FindAndPut(pid uint64) *pstypes.PS {
	ok, ps := s.Find(pid)
	if !ok {
		return nil
	}
	return ps
}

func (s *snapshotter) Put(ps *pstypes.PS) {
	if ps == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.procs[ps.PID] = ps
}

func (s *snapshotter) Write(evt *event.Event) error {
	if evt == nil || evt.PS == nil {
		return nil
	}
	s.Put(evt.PS)
	return nil
}

func (s *snapshotter) Remove(evt *event.Event) error {
	if evt == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.procs, evt.PID)
	return nil
}

func (s *snapshotter) Size() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint32(len(s.procs))
}

func (s *snapshotter) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.procs = make(map[uint64]*pstypes.PS)
	return nil
}

func (s *snapshotter) AddThread(evt *event.Event) error {
	if evt == nil || evt.PS == nil {
		return nil
	}
	ok, ps := s.Find(evt.PID)
	if !ok || ps == nil {
		s.Put(evt.PS)
		return nil
	}
	ps.AddThread(pstypes.Thread{Tid: evt.Tid, Pid: evt.PID})
	return nil
}

func (s *snapshotter) RemoveThread(pid uint64, tid uint64) error {
	ok, ps := s.Find(pid)
	if !ok || ps == nil {
		return nil
	}
	ps.RemoveThread(tid)
	return nil
}

func (s *snapshotter) AddMmap(evt *event.Event) error {
	if evt == nil || evt.PS == nil {
		return nil
	}
	ok, ps := s.Find(evt.PID)
	if !ok || ps == nil {
		s.Put(evt.PS)
		return nil
	}
	for _, mmap := range evt.PS.Mmaps {
		ps.AddMmap(mmap)
	}
	return nil
}

func (s *snapshotter) RemoveMmap(pid uint64, addr va.Address) error {
	ok, ps := s.Find(pid)
	if !ok || ps == nil {
		return nil
	}
	ps.RemoveMmap(addr)
	return nil
}
