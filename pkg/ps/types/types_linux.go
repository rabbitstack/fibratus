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

package types

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// PS encapsulates Linux process state and its allocated resources.
type PS struct {
	sync.RWMutex
	// PID is the thread group identifier. It is also the thread identifier of the main thread.
	PID uint64 `json:"pid"`
	// Ppid is the thread group identifier of the parent process.
	Ppid uint64 `json:"ppid"`
	// Name is the process name.
	Name string `json:"name"`
	// Cmdline is the full process command line.
	Cmdline string `json:"comm"`
	// Exe is the full path to the process executable.
	Exe string `json:"exe"`
	// Cwd is the current working directory of the process.
	Cwd string `json:"cwd"`
	// Args contains the process command-line arguments.
	Args []string `json:"args"`
	// StartTime is the wall-clock time when the process started.
	StartTime time.Time `json:"started"`
	// StartBootTime is the process start time measured from system boot.
	StartBootTime uint64 `json:"start_boot_time"`
	// UID is the real user identifier of the process.
	UID uint32 `json:"uid"`
	// GID is the real group identifier of the process.
	GID uint32 `json:"gid"`
	// Username is the name associated with UID.
	Username string `json:"username"`
	// Envs contains process environment variables indexed by name.
	Envs map[string]string `json:"envs"`
	// Parent references the parent process state when it is available.
	Parent *PS `json:"parent"`
	// Threads contains the threads that belong to this process.
	Threads map[uint64]Thread `json:"-"`
	// Mmaps contains the process memory mappings, including shared objects.
	Mmaps []Mmap `json:"mmaps"`
}

// UUID returns a stable identifier for this process instance.
func (ps *PS) UUID() uint64 {
	var key [16]byte
	binary.LittleEndian.PutUint64(key[:8], ps.PID)
	binary.LittleEndian.PutUint64(key[8:], ps.StartBootTime)
	h := fnv.New64a()
	_, _ = h.Write(key[:])
	return h.Sum64()
}

// String returns a string representation of the process state.
func (ps *PS) String() string {
	return fmt.Sprintf("Pid: %d\nPpid: %d\nName: %s\nCmdline: %s\nExe: %s", ps.PID, ps.Ppid, ps.Name, ps.Cmdline, ps.Exe)
}

// StringShort returns a compact string representation of the process state.
func (ps *PS) StringShort() string {
	return ps.String()
}

// Ancestors returns process ancestors as image name and process identifier pairs.
func (ps *PS) Ancestors() []string {
	var ancestors []string
	Walk(func(parent *PS) {
		ancestors = append(ancestors, fmt.Sprintf("%s (%d)", parent.Name, parent.PID))
	}, ps)
	return ancestors
}

// Thread stores identifiers for a Linux thread.
type Thread struct {
	// Tid is the thread identifier.
	Tid uint64
	// Pid is the thread group identifier to which the thread belongs.
	Pid uint64
}

// Mmap stores information about a process memory mapping.
type Mmap struct {
	// BaseAddress is the starting virtual address of the mapping.
	BaseAddress va.Address
	// Size is the mapping size in bytes.
	Size uint64
	// Protection is the mapping protection bitmask.
	Protection uint32
	// Type describes the mapping type.
	Type string
	// File is the path backing the mapping, if any.
	File string
}

// ProtectMask returns the mapping protection in mask notation.
func (m *Mmap) ProtectMask() string {
	return ""
}

// AddThread adds a thread to the process state.
func (ps *PS) AddThread(thread Thread) {
	ps.Lock()
	defer ps.Unlock()
	if ps.Threads == nil {
		ps.Threads = make(map[uint64]Thread)
	}
	ps.Threads[thread.Tid] = thread
}

// RemoveThread removes a thread from the process state.
func (ps *PS) RemoveThread(tid uint64) {
	ps.Lock()
	defer ps.Unlock()
	delete(ps.Threads, tid)
}

// AddMmap adds a memory mapping to the process state.
func (ps *PS) AddMmap(mmap Mmap) {
	ps.Mmaps = append(ps.Mmaps, mmap)
}

// RemoveMmap removes the memory mapping at the specified address.
func (ps *PS) RemoveMmap(addr va.Address) {
	for i, mmap := range ps.Mmaps {
		if mmap.BaseAddress == addr {
			ps.Mmaps = append(ps.Mmaps[:i], ps.Mmaps[i+1:]...)
			return
		}
	}
}

// FindMmap returns the memory mapping at the specified address.
func (ps *PS) FindMmap(addr va.Address) *Mmap {
	for i := range ps.Mmaps {
		if ps.Mmaps[i].BaseAddress == addr {
			return &ps.Mmaps[i]
		}
	}
	return nil
}
