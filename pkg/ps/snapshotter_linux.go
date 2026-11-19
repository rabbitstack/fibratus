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

	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// Snapshotter stores Linux process state for enrichment and rule evaluation.
type Snapshotter interface {
	// AddProcess appends or updates the process state.
	AddProcess(*pstypes.PS) error
	// RemoveProcess deletes the process state for the given process identifier.
	RemoveProcess(pid uint32) error
	// Find attempts to retrieve process state for the specified process identifier.
	Find(pid uint32) (bool, *pstypes.PS)
	// FindAndPut retrieves process state. Procfs fallback enrichment will be added
	// when Linux capture is wired.
	FindAndPut(pid uint32) *pstypes.PS
	// Put inserts the process state into the snapshotter.
	Put(*pstypes.PS)
	// Size returns the total number of process state items.
	Size() uint32
	// Close closes the process snapshotter and disposes allocated resources.
	Close() error
	// AddThread adds the thread to the process identified by the thread pid.
	AddThread(pstypes.Thread) error
	// RemoveThread removes the thread from the given process.
	RemoveThread(pid uint32, tid uint32) error
	// AddMmap adds a memory mapping to the specified process.
	AddMmap(pid uint32, mmap pstypes.Mmap) error
	// RemoveMmap removes a memory mapping at the given base address.
	RemoveMmap(pid uint32, addr va.Address) error
}

type snapshotter struct {
	mu    sync.RWMutex
	procs map[uint32]*pstypes.PS
}

// NewSnapshotter builds an in-memory Linux process snapshotter.
func NewSnapshotter() Snapshotter {
	return &snapshotter{procs: make(map[uint32]*pstypes.PS)}
}

func (s *snapshotter) Find(pid uint32) (bool, *pstypes.PS) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ps, ok := s.procs[pid]
	return ok, ps
}

func (s *snapshotter) FindAndPut(pid uint32) *pstypes.PS {
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

func (s *snapshotter) AddProcess(ps *pstypes.PS) error {
	s.Put(ps)
	return nil
}

func (s *snapshotter) RemoveProcess(pid uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.procs, pid)
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
	s.procs = make(map[uint32]*pstypes.PS)
	return nil
}

func (s *snapshotter) AddThread(thread pstypes.Thread) error {
	ok, ps := s.Find(thread.Pid)
	if !ok || ps == nil {
		return nil
	}
	ps.AddThread(thread)
	return nil
}

func (s *snapshotter) RemoveThread(pid uint32, tid uint32) error {
	ok, ps := s.Find(pid)
	if !ok || ps == nil {
		return nil
	}
	ps.RemoveThread(tid)
	return nil
}

func (s *snapshotter) AddMmap(pid uint32, mmap pstypes.Mmap) error {
	ok, ps := s.Find(pid)
	if !ok || ps == nil {
		return nil
	}
	ps.AddMmap(mmap)
	return nil
}

func (s *snapshotter) RemoveMmap(pid uint32, addr va.Address) error {
	ok, ps := s.Find(pid)
	if !ok || ps == nil {
		return nil
	}
	ps.RemoveMmap(addr)
	return nil
}
