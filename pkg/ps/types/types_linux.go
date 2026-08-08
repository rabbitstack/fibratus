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
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// PE is a placeholder for PE metadata on Linux builds.
// Linux process images are ELF; this field exists so shared
// formatters/templates compile without Windows PE types.
type PE struct{}

func (p *PE) String() string { return "" }

type PS struct {
	sync.RWMutex
	PID           uint32            `json:"pid"`
	Ppid          uint32            `json:"ppid"`
	Name          string            `json:"name"`
	Cmdline       string            `json:"comm"`
	Exe           string            `json:"exe"`
	Cwd           string            `json:"cwd"`
	Args          []string          `json:"args"`
	StartTime     time.Time         `json:"started"`
	StartBootTime uint64            `json:"start_boot_time"`
	UID           uint32            `json:"uid"`
	GID           uint32            `json:"gid"`
	Username            string            `json:"username"`
	Domain              string            `json:"domain"`
	SID                 string            `json:"sid"`
	SessionID           uint32            `json:"session_id"`
	TokenIntegrityLevel string            `json:"token_integrity_level"`
	TokenElevationType  string            `json:"token_elevation_type"`
	IsTokenElevated     bool              `json:"is_token_elevated"`
	IsWOW64             bool              `json:"is_wow_64"`
	IsPackaged          bool              `json:"is_packaged"`
	IsProtected         bool              `json:"is_protected"`
	Envs                map[string]string `json:"envs"`
	Parent              *PS               `json:"parent"`
	Threads             map[uint32]Thread `json:"-"`
	Mmaps               []Mmap            `json:"mmaps"`
	Modules             []Module          `json:"modules"`
	PE                  *PE               `json:"-"`
}

func (ps *PS) String() string {
	return fmt.Sprintf("Pid: %d\nPpid: %d\nName: %s\nCmdline: %s\nExe: %s", ps.PID, ps.Ppid, ps.Name, ps.Cmdline, ps.Exe)
}

func (ps *PS) StringShort() string {
	return ps.String()
}

func (ps *PS) Ancestors() []string {
	var ancestors []string
	Walk(func(parent *PS) {
		ancestors = append(ancestors, fmt.Sprintf("%s (%d)", parent.Name, parent.PID))
	}, ps)
	return ancestors
}

type Thread struct {
	Tid          uint32
	Pid          uint32
	StartAddress va.Address
	UstackBase   va.Address
	UstackLimit  va.Address
	KstackBase   va.Address
	KstackLimit  va.Address
}

type Module struct {
	Name        string
	BaseAddress va.Address
	Size        uint64
	Checksum    uint32
}

type Mmap struct {
	BaseAddress va.Address
	Size        uint64
	Protection  uint32
	Type        string
	File        string
}

func (m *Mmap) ProtectMask() string {
	return ""
}

func (ps *PS) AddThread(thread Thread) {
	if ps.Threads == nil {
		ps.Threads = make(map[uint32]Thread)
	}
	ps.Threads[thread.Tid] = thread
}

func (ps *PS) RemoveThread(tid uint32) {
	delete(ps.Threads, tid)
}

func (ps *PS) AddMmap(mmap Mmap) {
	ps.Mmaps = append(ps.Mmaps, mmap)
}

func (ps *PS) RemoveMmap(addr va.Address) {
	for i, mmap := range ps.Mmaps {
		if mmap.BaseAddress == addr {
			ps.Mmaps = append(ps.Mmaps[:i], ps.Mmaps[i+1:]...)
			return
		}
	}
}

func (ps *PS) FindMmap(addr va.Address) *Mmap {
	for i := range ps.Mmaps {
		if ps.Mmaps[i].BaseAddress == addr {
			return &ps.Mmaps[i]
		}
	}
	return nil
}

func (ps *PS) IsSvchost() bool {
	return strings.EqualFold(ps.Name, "svchost.exe")
}
