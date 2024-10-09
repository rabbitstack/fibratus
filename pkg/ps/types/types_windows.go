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

package types

import (
	"encoding/binary"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/cmdline"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"path/filepath"
	"strings"
	"sync"

	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kcap/section"
	"github.com/rabbitstack/fibratus/pkg/pe"

	"github.com/rabbitstack/fibratus/pkg/util/bootid"
	"time"
)

// PS encapsulates process' state such as allocated resources and other metadata.
type PS struct {
	sync.RWMutex
	// PID is the identifier of this process. This value is valid from the time a process is created until it is terminated.
	PID uint32 `json:"pid"`
	// Ppipd represents the parent of this process. Process identifier numbers are reused, so they only identify a process
	// for the lifetime of that process. It is possible that the process identified by `Ppid` is terminated,
	// so `Ppid` may not refer to a running process. It is also possible that `Ppid` incorrectly refers
	// to a process that reuses a process identifier.
	Ppid uint32 `json:"ppid"`
	// Name is the process' image name including file extension (e.g. cmd.exe)
	Name string `json:"name"`
	// Cmdline is the full process' command line (e.g. C:\Windows\system32\cmd.exe /cdir /-C /W)
	Cmdline string `json:"comm"`
	// Exe is the full name of the process' executable (e.g. C:\Windows\system32\cmd.exe)
	Exe string `json:"exe"`
	// Cwd designates the current working directory of the process.
	Cwd string `json:"cwd"`
	// SID is the security identifier under which this process is run. (e.g. S-1-5-32-544)
	SID string `json:"sid"`
	// Args contains process' command line arguments (e.g. /cdir, /-C, /W)
	Args []string `json:"args"`
	// SessionID is the unique identifier for the current session.
	SessionID uint32 `json:"session"`
	// Envs contains process' environment variables indexed by env variable name.
	Envs map[string]string `json:"envs"`
	// Threads contains all the threads running in the address space of this process.
	Threads map[uint32]Thread `json:"-"`
	// Modules contains all the modules loaded by the process.
	Modules []Module `json:"modules"`
	// FileMappings contains all memory-mapped data files.
	FileMappings []Mmap
	// Handles represents the collection of handles allocated by the process.
	Handles htypes.Handles `json:"handles"`
	// PE stores the PE (Portable Executable) metadata.
	PE *pe.PE `json:"pe"`
	// Parent represents the reference to the parent process.
	Parent *PS `json:"parent"`
	// StartTime represents the process start time.
	StartTime time.Time `json:"started"`
	// uuid is a unique process identifier derived from boot ID and process sequence number
	uuid uint64
	// Username represents the username under which the process is run.
	Username string `json:"username"`
	// Domain represents the domain under which the process is run. (e.g. NT AUTHORITY)
	Domain string `json:"domain"`
	// IsWOW64 indicates if this is 32-bit process created in 64-bit Windows system (Windows on Windows)
	IsWOW64 bool `json:"is_wow_64"`
	// IsPackaged denotes that the process is packaged with the MSIX technology and thus has
	// associated package identity.
	IsPackaged bool `json:"is_packaged"`
	// IsProtected denotes a protected process. The system restricts access to protected
	// processes and the threads of protected processes.
	IsProtected bool `json:"is_protected"`
}

// UUID is meant to offer a more robust version of process ID that
// is resistant to being repeated. Process start key was introduced
// in Windows 10 1507 and is derived from _KUSER_SHARED_DATA.BootId and
// EPROCESS.SequenceNumber both of which increment and are unlikely to
// overflow. This method uses a combination of process start key and boot id
// to fabric a unique process identifier. If this is not possible, the uuid
// is computed by using the process start time.
func (ps *PS) UUID() uint64 {
	if ps.uuid != 0 {
		return ps.uuid
	}
	// assume the uuid is derived from boot ID and process start time
	ps.uuid = (bootid.Read() << 30) + uint64(ps.PID) | uint64(ps.StartTime.UnixNano())
	maj, _, patch := windows.RtlGetNtVersionNumbers()
	if maj >= 10 && patch >= 1507 {
		seqNum := querySequenceNumber(ps.PID)
		// prefer the most robust variant of the uuid which uses the
		// process sequence number obtained from the process object
		if seqNum != 0 {
			ps.uuid = (bootid.Read() << 30) | seqNum
		}
	}
	return ps.uuid
}

// ProcessSequenceNumber contains the unique process sequence number.
type ProcessSequenceNumber struct {
	Seq [8]byte
}

func querySequenceNumber(pid uint32) uint64 {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return 0
	}
	defer windows.Close(proc)
	seq, err := sys.QueryInformationProcess[ProcessSequenceNumber](proc, windows.ProcessSequenceNumber)
	if err != nil {
		return 0
	}
	return binary.BigEndian.Uint64(seq.Seq[:])
}

// String returns a string representation of the process' state.
func (ps *PS) String() string {
	parent := ps.Parent
	if parent != nil {
		return fmt.Sprintf(`
		Pid:  %d
		Ppid: %d
		Name: %s
		Parent name: %s
		Cmdline: %s
		Parent cmdline: %s
		Exe:  %s
		Cwd:  %s
		SID:  %s
		Username: %s
		Domain: %s
		Args: %s
		Session ID: %d
		Envs: %v
		`,
			ps.PID,
			ps.Ppid,
			ps.Name,
			parent.Name,
			ps.Cmdline,
			parent.Cmdline,
			ps.Exe,
			ps.Cwd,
			ps.SID,
			ps.Username,
			ps.Domain,
			ps.Args,
			ps.SessionID,
			ps.Envs,
		)
	}
	return fmt.Sprintf(`
		Pid:  %d
		Ppid: %d
		Name: %s
		Cmdline: %s
		Exe:  %s
		Cwd:  %s
		SID:  %s
		Username: %s
		Domain: %s
		Args: %s
		Session ID: %d
		Envs: %v
		`,
		ps.PID,
		ps.Ppid,
		ps.Name,
		ps.Cmdline,
		ps.Exe,
		ps.Cwd,
		ps.SID,
		ps.Username,
		ps.Domain,
		ps.Args,
		ps.SessionID,
		ps.Envs,
	)
}

// Ancestors returns all ancestors of this process. The string slice contains
// the process image name followed by the process id.
func (ps *PS) Ancestors() []string {
	ancestors := make([]string, 0)
	walk := func(proc *PS) {
		ancestors = append(ancestors, fmt.Sprintf("%s (%d)", proc.Name, proc.PID))
	}
	Walk(walk, ps)
	return ancestors
}

// Thread stores metadata about a thread that's executing in process's address space.
type Thread struct {
	// Tid is the unique identifier of thread inside the process.
	Tid uint32
	// Pid is the identifier of the process to which this thread pertains.
	Pid uint32
	// IOPrio represents an I/O priority hint for scheduling I/O operations generated by the thread.
	IOPrio uint8
	// BasePrio is the scheduler priority of the thread.
	BasePrio uint8
	// PagePrio is a memory page priority hint for memory pages accessed by the thread.
	PagePrio uint8
	// UstackBase is the base address of the thread's user space stack.
	UstackBase va.Address
	// UstackLimit is the limit of the thread's user space stack.
	UstackLimit va.Address
	// KStackBase is the base address of the thread's kernel space stack.
	KstackBase va.Address
	// KstackLimit is the limit of the thread's kernel space stack.
	KstackLimit va.Address
	// StartAddress is thread start address.
	StartAddress va.Address
}

// String returns the thread as a human-readable string.
func (t Thread) String() string {
	return fmt.Sprintf("ID: %d IO prio: %d, Base prio: %d, Page prio: %d, Ustack base: %s, Ustack limit: %s, Kstack base: %s, Kstack limit: %s, Start address: %s", t.Tid, t.IOPrio, t.BasePrio, t.PagePrio, t.UstackBase, t.UstackLimit, t.KstackBase, t.UstackLimit, t.StartAddress)
}

// Module represents the data for all dynamic libraries/executables that reside in the process' address space.
type Module struct {
	// Size designates the size in bytes of the image file.
	Size uint64
	// Checksum is the checksum of the image file.
	Checksum uint32
	// Name represents the full path of this image.
	Name string
	// BaseAddress is the base address of process in which the image is loaded.
	BaseAddress va.Address
	// DefaultBaseAddress is the default base address.
	DefaultBaseAddress va.Address
	// SignatureLevel designates the image signature level. (e.g. MICROSOFT)
	SignatureLevel uint32
	// SignatureType designates the image signature type (e.g. EMBEDDED)
	SignatureType uint32
}

// String returns the string representation of the module.
func (m Module) String() string {
	return fmt.Sprintf("Name: %s, Size: %d, Checksum: %d, Base address: %s, Default base address: %s", m.Name, m.Size, m.Checksum, m.BaseAddress, m.DefaultBaseAddress)
}

// IsExecutable determines if the loaded module is an executable.
func (m Module) IsExecutable() bool { return strings.ToLower(filepath.Ext(m.Name)) == ".exe" }

// Mmap stores information of the memory-mapped file.
type Mmap struct {
	File        string
	BaseAddress va.Address
	Size        uint64
}

// New produces a new process state.
func New(pid, ppid uint32, name, cmndline, exe string, sid *windows.SID, sessionID uint32) *PS {
	ps := &PS{
		PID:          pid,
		Ppid:         ppid,
		Name:         name,
		Cmdline:      cmndline,
		Exe:          exe,
		Args:         cmdline.Split(cmndline),
		SID:          sid.String(),
		SessionID:    sessionID,
		Threads:      make(map[uint32]Thread),
		Modules:      make([]Module, 0),
		Handles:      make([]htypes.Handle, 0),
		FileMappings: make([]Mmap, 0),
	}
	ps.Username, ps.Domain, _, _ = sid.LookupAccount("")
	return ps
}

// NewFromKcap reconstructs the state of the process from the capture file.
func NewFromKcap(buf []byte, sec section.Section) (*PS, error) {
	ps := PS{
		Args:         make([]string, 0),
		Envs:         make(map[string]string),
		Handles:      make([]htypes.Handle, 0),
		Modules:      make([]Module, 0),
		Threads:      make(map[uint32]Thread),
		FileMappings: make([]Mmap, 0),
	}
	if err := ps.Unmarshal(buf, sec); err != nil {
		return nil, err
	}
	return &ps, nil
}

// AddThread adds a thread to process's state descriptor.
func (ps *PS) AddThread(thread Thread) {
	ps.Lock()
	defer ps.Unlock()
	ps.Threads[thread.Tid] = thread
}

// RemoveThread eliminates a thread from the process's state.
func (ps *PS) RemoveThread(tid uint32) {
	ps.Lock()
	defer ps.Unlock()
	delete(ps.Threads, tid)
}

// AddHandle adds a new handle to this process state.
func (ps *PS) AddHandle(handle htypes.Handle) {
	ps.Handles = append(ps.Handles, handle)
}

// RemoveHandle removes a handle with specified identifier from the list of allocated handles.
func (ps *PS) RemoveHandle(handle windows.Handle) {
	for i, h := range ps.Handles {
		if h.Num == handle {
			ps.Handles = append(ps.Handles[:i], ps.Handles[i+1:]...)
			break
		}
	}
}

// AddModule adds a new module to this process state.
func (ps *PS) AddModule(mod Module) {
	m := ps.FindModule(mod.Name)
	if m != nil {
		return
	}
	ps.Modules = append(ps.Modules, mod)
}

// RemoveModule removes a specified module from this process state.
func (ps *PS) RemoveModule(path string) {
	for i, mod := range ps.Modules {
		if filepath.Base(mod.Name) == filepath.Base(path) {
			ps.Modules = append(ps.Modules[:i], ps.Modules[i+1:]...)
			break
		}
	}
}

// FindModule finds the module by name.
func (ps *PS) FindModule(path string) *Module {
	for _, mod := range ps.Modules {
		if filepath.Base(mod.Name) == filepath.Base(path) {
			return &mod
		}
	}
	return nil
}

// FindModuleByVa finds the module name by
// probing the range of the given virtual address.
func (ps *PS) FindModuleByVa(addr va.Address) *Module {
	for _, mod := range ps.Modules {
		if addr >= mod.BaseAddress && addr <= mod.BaseAddress.Inc(mod.Size) {
			return &mod
		}
	}
	return nil
}

// MapFile adds a new data-mapped file this process state.
func (ps *PS) MapFile(mmap Mmap) {
	ps.FileMappings = append(ps.FileMappings, mmap)
}

// UnmapFile removes a specified data-mapped file from this process state.
func (ps *PS) UnmapFile(addr va.Address) {
	for i, mmap := range ps.FileMappings {
		if mmap.BaseAddress == addr {
			ps.FileMappings = append(ps.FileMappings[:i], ps.FileMappings[i+1:]...)
			break
		}
	}
}

// FindMappingByVa finds the memory-mapped file
// by probing the range of the given virtual address.
func (ps *PS) FindMappingByVa(addr va.Address) string {
	for _, mmap := range ps.FileMappings {
		if addr >= mmap.BaseAddress && addr <= mmap.BaseAddress.Inc(mmap.Size) {
			return mmap.File
		}
	}
	return "unbacked"
}
