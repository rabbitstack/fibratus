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

// LinuxSnapshotter stores Linux process state for enrichment and rule evaluation.
type LinuxSnapshotter interface {
	Resolver
	Write(*event.Event) error
	Remove(*event.Event) error
	UpsertSnapshot(*pstypes.PS)
	Put(*pstypes.PS)
	Size() uint32
	Close() error
	AddThread(*event.Event) error
	RemoveThread(pid uint32, tid uint32) error
	AddMmap(*event.Event) error
	RemoveMmap(pid uint32, addr va.Address) error
}

type linuxSnapshotter struct {
	mu    sync.RWMutex
	procs map[uint32]*pstypes.PS
}

// NewLinuxSnapshotter builds an in-memory Linux process snapshotter.
func NewLinuxSnapshotter() LinuxSnapshotter {
	return &linuxSnapshotter{procs: make(map[uint32]*pstypes.PS)}
}

func (s *linuxSnapshotter) Find(pid uint32) (bool, *pstypes.PS) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ps, ok := s.procs[pid]
	return ok, ps
}

func (s *linuxSnapshotter) Put(ps *pstypes.PS) {
	if ps == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.procs[ps.PID] = ps
}

func (s *linuxSnapshotter) UpsertSnapshot(ps *pstypes.PS) {
	s.Put(ps)
}

func (s *linuxSnapshotter) Write(evt *event.Event) error {
	if evt == nil || evt.PS == nil {
		return nil
	}
	s.Put(evt.PS)
	return nil
}

func (s *linuxSnapshotter) Remove(evt *event.Event) error {
	if evt == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.procs, evt.PID)
	return nil
}

func (s *linuxSnapshotter) Size() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint32(len(s.procs))
}

func (s *linuxSnapshotter) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.procs = make(map[uint32]*pstypes.PS)
	return nil
}

func (s *linuxSnapshotter) AddThread(evt *event.Event) error {
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

func (s *linuxSnapshotter) RemoveThread(pid uint32, tid uint32) error {
	ok, ps := s.Find(pid)
	if !ok || ps == nil {
		return nil
	}
	ps.RemoveThread(tid)
	return nil
}

func (s *linuxSnapshotter) AddMmap(evt *event.Event) error {
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

func (s *linuxSnapshotter) RemoveMmap(pid uint32, addr va.Address) error {
	ok, ps := s.Find(pid)
	if !ok || ps == nil {
		return nil
	}
	ps.RemoveMmap(addr)
	return nil
}
