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
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/hashers"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
	"golang.org/x/sys/windows"

	"github.com/rabbitstack/fibratus/pkg/cap/section"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/pe"

	"time"

	"github.com/rabbitstack/fibratus/pkg/util/bootid"
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

	// Mmaps contains all memory mappings.
	Mmaps []Mmap

	// Handles represents the collection of handles allocated by the process.
	Handles htypes.Handles `json:"handles"`

	// PE stores the PE (Portable Executable) metadata.
	PE *pe.PE `json:"pe"`

	// Parent represents the reference to the parent process.
	Parent *PS `json:"parent"`

	// StartTime represents the process start time.
	StartTime time.Time `json:"started"`

	// SeqNum is the process sequence number reported by the Kernel Process provider
	// in the process creation events. It is zero when the sequence number is not known.
	SeqNum uint64 `json:"-"`

	// ParentSeqNum is the sequence number of the parent process, as reported by the
	// Kernel Process provider. It allows telling the actual parent apart from a different
	// process that reused the parent pid. It is zero when it is not known.
	ParentSeqNum uint64 `json:"-"`

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

	// TokenIntegrityLevel designates the process token integrity level. (e.g. High)
	// Integrity level defines the trust between the process and a securable object.
	TokenIntegrityLevel string `json:"token_integrity_level"`

	// TokenElevationType designates the process token elevation type. (e.g. Limited)
	TokenElevationType string `json:"token_elevation_type"`

	// IsTokenElevated indicates if the process token is elevated.
	IsTokenElevated bool `json:"is_token_elevated"`

	// IsCreatedFromSystemLogger is the metadata attribute that indicates if the
	// process state is created from the event published by the NT kernel logger.
	IsCreatedFromSystemLogger bool `json:"-"`

	// uuid is a unique process identifier derived from boot ID and process sequence number
	uuid uint64
	// uuidExact indicates the uuid was derived from the process sequence number
	// rather than from the hash of pid and start time
	uuidExact bool
	// uuidLock guards the lazy initialization of the uuid, since it can be requested concurrently
	uuidLock sync.Mutex

	// modules are process modules obtained by direct invocation to the API call.
	modules  []sys.ProcessModule
	onceMods sync.Once
}

// minSeqNumBuild is the build number of Windows 10 1507, the first
// release that exposes the process sequence number (start key).
const minSeqNumBuild = 10240

// UUID is meant to offer a more robust version of process ID that
// is resistant to being repeated. Process start key was introduced
// in Windows 10 1507 and is derived from _KUSER_SHARED_DATA.BootId and
// EPROCESS.SequenceNumber both of which increment and are unlikely to
// overflow. This method uses a combination of process start key and boot id
// to fabric a unique process identifier. If this is not possible, the uuid
// is computed by using the process start time.
func (ps *PS) UUID() uint64 {
	ps.uuidLock.Lock()
	defer ps.uuidLock.Unlock()
	if ps.uuid != 0 {
		return ps.uuid
	}

	boot := bootid.Read()
	// the sequence number delivered by the process creation event is the
	// cheapest and the most reliable source, since it doesn't depend on
	// the process being alive at the time of the request
	if ps.SeqNum != 0 {
		ps.uuid, ps.uuidExact = seqUUID(boot, ps.SeqNum), true
		return ps.uuid
	}

	// assume the uuid is derived from boot ID, process id and process start time
	ps.uuid = uuid(boot, ps.PID, ps.StartTime)

	maj, _, build := windows.RtlGetNtVersionNumbers()
	if maj >= 10 && build >= minSeqNumBuild {
		seqNum := querySequenceNumber(ps.PID)
		// prefer the most robust variant of the uuid which uses the
		// process sequence number obtained from the process object
		if seqNum != 0 {
			ps.uuid, ps.uuidExact = seqUUID(boot, seqNum), true
		}
	}

	return ps.uuid
}

// InitUUID initializes the process UUID. It is the
// imperative version of the lazily evaluated UUID()
// method.
func (ps *PS) InitUUID() {
	ps.UUID()
}

// IsUUIDExact indicates whether the UUID has been derived from the process sequence
// number, in which case two processes have the same UUID only if they are the same
// process instance.
func (ps *PS) IsUUIDExact() bool {
	ps.uuidLock.Lock()
	defer ps.uuidLock.Unlock()
	return ps.uuidExact
}

// ParentUUID returns the UUID of the parent process derived from the parent sequence
// number reported by the process creation event, or zero if the number is not known.
func (ps *PS) ParentUUID() uint64 {
	ps.uuidLock.Lock()
	seq := ps.ParentSeqNum
	ps.uuidLock.Unlock()
	if seq == 0 {
		return 0
	}
	return seqUUID(bootid.Read(), seq)
}

// uuid derives the process identifier from the boot ID, pid and start
// time by hashing them. Combining the values with bitwise operators would
// let the large nanosecond timestamp mask the bits of the other components.
func uuid(boot uint64, pid uint32, start time.Time) uint64 {
	var b [20]byte
	binary.LittleEndian.PutUint64(b[0:], boot)
	binary.LittleEndian.PutUint32(b[8:], pid)
	binary.LittleEndian.PutUint64(b[12:], uint64(start.UnixNano()))
	uuid := hashers.FnvUint64(b[:])
	if uuid == 0 {
		// zero denotes the uuid that has not been initialized yet
		uuid = 1
	}
	return uuid
}

// seqUUID derives the process identifier from the boot ID and the process
// sequence number. This is the process start key.
func seqUUID(boot, seq uint64) uint64 {
	return (boot << 30) | seq
}

// InheritSeqNum takes over the process and parent sequence numbers from
// the given state, if they are not known to this one.
func (ps *PS) InheritSeqNum(from *PS) {
	seq, pseq := from.seqNum(), from.ParentSeqNum
	ps.uuidLock.Lock()
	defer ps.uuidLock.Unlock()
	if ps.SeqNum == 0 {
		ps.SeqNum = seq
	}
	if ps.ParentSeqNum == 0 {
		ps.ParentSeqNum = pseq
	}
}

// sequence returns the process sequence number. It is guarded by the same
// lock as the UUID, since the UUID is derived from it.
func (ps *PS) seqNum() uint64 {
	ps.uuidLock.Lock()
	defer ps.uuidLock.Unlock()
	return ps.SeqNum
}

// AssignUUID assigns the UUID from the given
// process if the UUID has been initialized.
func (ps *PS) AssignUUID(proc *PS) {
	proc.uuidLock.Lock()
	uuid := proc.uuid
	uuidExact := proc.uuidExact
	proc.uuidLock.Unlock()
	if uuid == 0 {
		return
	}
	ps.uuidLock.Lock()
	ps.uuid = uuid
	ps.uuidExact = uuidExact
	ps.uuidLock.Unlock()
}

// Merge merges the token properties, sequence numbers and the full executable
// path carried by the state derived from the internal events into this state.
func (ps *PS) Merge(proc *PS) {
	ps.Lock()
	defer ps.Unlock()
	ps.TokenIntegrityLevel = proc.TokenIntegrityLevel
	ps.TokenElevationType = proc.TokenElevationType
	ps.IsTokenElevated = proc.IsTokenElevated
	if strings.EqualFold(ps.Name, filepath.Base(proc.Exe)) {
		ps.Exe = proc.Exe
	}
	ps.InheritSeqNum(proc)
}

// Equals reports whether the other process state may describe the same
// process instance as this one. The start times are compared with the given
// tolerance, because they originate from different providers. Unknown start
// times and sequence numbers are not held against the match.
func (ps *PS) Equals(other *PS, skew time.Duration) bool {
	if a, b := ps.seqNum(), other.seqNum(); a != 0 && b != 0 {
		return a == b
	}
	if ps.StartTime.IsZero() || other.StartTime.IsZero() {
		return true
	}
	d := ps.StartTime.Sub(other.StartTime)
	if d < 0 {
		d = -d
	}
	return d <= skew
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
	// the sequence number is stored in the native byte order
	return binary.LittleEndian.Uint64(seq.Seq[:])
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
		Exe: %s
		Cwd: %s
		SID: %s
		Integrity level: %s
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
			ps.TokenIntegrityLevel,
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
		Exe: %s
		Cwd: %s
		SID: %s
		Integrity level: %s
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
		ps.TokenIntegrityLevel,
		ps.Username,
		ps.Domain,
		ps.Args,
		ps.SessionID,
		ps.Envs,
	)
}

// StringShort returns a string representation of the process' state
// by removing some verbose attributes such as the env variables block.
func (ps *PS) StringShort() string {
	parent := ps.Parent
	if parent != nil {
		return fmt.Sprintf(`
		Pid:  %d
		Ppid: %d
		Name: %s
		Parent name: %s
		Cmdline: %s
		Parent cmdline: %s
		Exe: %s
		Cwd: %s
		SID: %s
		Integrity level: %s
		Username: %s
		Domain: %s
		Args: %s
		Session ID: %d
		Ancestors: %s
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
			ps.TokenIntegrityLevel,
			ps.Username,
			ps.Domain,
			ps.Args,
			ps.SessionID,
			strings.Join(ps.Ancestors(), " > "),
		)
	}
	return fmt.Sprintf(`
		Pid:  %d
		Ppid: %d
		Name: %s
		Cmdline: %s
		Exe: %s
		Cwd: %s
		SID: %s
		Integrity level: %s
		Username: %s
		Domain: %s
		Args: %s
		Session ID: %d
		Ancestors: %s
	`,
		ps.PID,
		ps.Ppid,
		ps.Name,
		ps.Cmdline,
		ps.Exe,
		ps.Cwd,
		ps.SID,
		ps.TokenIntegrityLevel,
		ps.Username,
		ps.Domain,
		ps.Args,
		ps.SessionID,
		strings.Join(ps.Ancestors(), " > "),
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

// IsSeclogonSvc returns true if this is the Secondary Logon Service process.
func (ps *PS) IsSeclogonSvc() bool {
	return ps.IsSvchost() && strings.HasSuffix(ps.Cmdline, "-s seclogon")
}

// IsAppinfoSvc returns true if this is the AppInfo Service process.
func (ps *PS) IsAppinfoSvc() bool {
	return ps.IsSvchost() && strings.HasSuffix(ps.Cmdline, "-s Appinfo")
}

// IsSvchost returns true if this is the Service Host process.
func (ps *PS) IsSvchost() bool {
	return wildcard.Match(`?:\windows\system32\svchost.exe`, ps.Exe, false)
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
	return fmt.Sprintf("ID: %d IO prio: %d, Base prio: %d, Page prio: %d, Ustack base: %s, Ustack limit: %s, Kstack base: %s, Kstack limit: %s, Start address: %s", t.Tid, t.IOPrio, t.BasePrio, t.PagePrio, t.UstackBase, t.UstackLimit, t.KstackBase, t.KstackLimit, t.StartAddress)
}

// Module represents the data for all dynamic libraries/executables that reside in the process' address space.
type Module struct {
	// Size designates the size in bytes of the module file.
	Size uint64
	// Checksum is the checksum of the module file.
	Checksum uint32
	// Name represents the full path of module image.
	Name string
	// BaseAddress is the base address of process in which the module is loaded.
	BaseAddress va.Address
	// DefaultBaseAddress is the default base address.
	DefaultBaseAddress va.Address
	// SignatureLevel designates the module signature level. (e.g. MICROSOFT)
	SignatureLevel uint32
	// SignatureType designates the module signature type (e.g. EMBEDDED)
	SignatureType uint32
	// TimedateStamp that is produced by the linker.
	TimedateStamp uint32
}

// String returns the string representation of the module.
func (m Module) String() string {
	return fmt.Sprintf("Name: %s, Size: %d, Checksum: %d, Base address: %s, Default base address: %s", m.Name, m.Size, m.Checksum, m.BaseAddress, m.DefaultBaseAddress)
}

// IsExecutable determines if the loaded module is an executable.
func (m Module) IsExecutable() bool { return strings.ToLower(filepath.Ext(m.Name)) == ".exe" }

// IsNTDLL determines if the module is the native ntdll module.
func (m Module) IsNTDLL() bool { return strings.EqualFold(filepath.Base(m.Name), "ntdll.dll") }

// Mmap stores information related to the memory mapping.
type Mmap struct {
	// BaseAddress represents the address where the view of section is mapped.
	BaseAddress va.Address
	// Size indicates the size of the mapped view of section.
	Size uint64
	// Protection is the bitmask with view protection rights.
	Protection uint32
	// Type represents the type of the view of section (e.g. IMAGE, DATA, PAGEFILE)
	Type string
	// File if the view is backed by the file object, this field indicates
	// the file path of the mapped image/data file.
	File string
}

var mmapProtections = map[uint32]string{
	sys.SectionR:   "R",
	sys.SectionX:   "X",
	sys.SectionRW:  "RW",
	sys.SectionRX:  "RX",
	sys.SectionRWX: "RWX",
	sys.SectionWC:  "WC",
	sys.SectionWXC: "WXC",
	sys.SectionWCB: "WCB",
	sys.SectionNC:  "NC",
}

// ProtectMask returns the view protection in mask notation.
func (m *Mmap) ProtectMask() string {
	var (
		b strings.Builder
		s string
	)

	f := m.Protection

	for protect, mask := range mmapProtections {
		if (f&protect) == protect && protect != 0 {
			b.WriteString(s)
			b.WriteString(mask)
			s = "|"
			f &= ^protect
		}
	}

	return b.String()
}

// NewFromCapture reconstructs the state of the process from the capture file.
func NewFromCapture(buf []byte, sec section.Section) (*PS, error) {
	ps := PS{
		Args:    make([]string, 0),
		Envs:    make(map[string]string),
		Handles: make([]htypes.Handle, 0),
		Modules: make([]Module, 0),
		Threads: make(map[uint32]Thread),
		Mmaps:   make([]Mmap, 0),
	}
	if err := ps.Unmarshal(buf, sec); err != nil {
		return nil, err
	}
	return &ps, nil
}

// AddThread adds a thread to process's state descriptor.
func (ps *PS) AddThread(thread Thread) bool {
	ps.Lock()
	defer ps.Unlock()
	_, exists := ps.Threads[thread.Tid]
	ps.Threads[thread.Tid] = thread
	return !exists
}

// RemoveThread eliminates a thread from the process's state.
func (ps *PS) RemoveThread(tid uint32) bool {
	ps.Lock()
	defer ps.Unlock()
	_, exists := ps.Threads[tid]
	delete(ps.Threads, tid)
	return exists
}

// AddHandle adds a new handle to this process state.
func (ps *PS) AddHandle(handle htypes.Handle) {
	ps.Lock()
	defer ps.Unlock()
	ps.Handles = append(ps.Handles, handle)
}

// RemoveHandle removes a handle with specified identifier from the list of allocated handles.
func (ps *PS) RemoveHandle(handle windows.Handle) {
	ps.Lock()
	defer ps.Unlock()
	for i, h := range ps.Handles {
		if h.Num == handle {
			ps.Handles = slices.Delete(ps.Handles, i, i+1)
			break
		}
	}
}

// AddModule adds a new module to this process state. The module
// is ignored if there is already a module with the same base address.
func (ps *PS) AddModule(mod Module) bool {
	ps.Lock()
	defer ps.Unlock()
	if strings.EqualFold(ps.Name, filepath.Base(mod.Name)) && len(ps.Exe) < len(mod.Name) {
		// if the module is loaded for the process executable, and
		// we don't have the full executable path, override with
		// the one from the module path
		ps.Exe = mod.Name
	}
	if ps.findModuleByAddr(mod.BaseAddress) != nil {
		return false
	}
	ps.Modules = append(ps.Modules, mod)
	return true
}

// RemoveModule removes a specified module from this process state.
func (ps *PS) RemoveModule(addr va.Address) bool {
	ps.Lock()
	defer ps.Unlock()
	for i, mod := range ps.Modules {
		if mod.BaseAddress == addr {
			ps.Modules = slices.Delete(ps.Modules, i, i+1)
			return true
		}
	}
	return false
}

// FindModule finds the module by name. The returned module is a copy,
// so it remains valid even if the module is subsequently removed.
func (ps *PS) FindModule(path string) *Module {
	ps.RLock()
	defer ps.RUnlock()
	for i := range ps.Modules {
		if filepath.Base(ps.Modules[i].Name) == filepath.Base(path) {
			mod := ps.Modules[i]
			return &mod
		}
	}
	return nil
}

// FindModuleByAddr finds the module by its base address. The returned
// module is a copy, so it remains valid even if the module is removed.
func (ps *PS) FindModuleByAddr(addr va.Address) *Module {
	ps.RLock()
	defer ps.RUnlock()
	if m := ps.findModuleByAddr(addr); m != nil {
		mod := *m
		return &mod
	}
	return nil
}

// AddMmap adds a new memory mapping for this process state.
func (ps *PS) AddMmap(mmap Mmap) {
	ps.Lock()
	defer ps.Unlock()
	ps.Mmaps = append(ps.Mmaps, mmap)
}

// RemoveMmap removes the memory mapping at the specified address.
func (ps *PS) RemoveMmap(addr va.Address) bool {
	ps.Lock()
	defer ps.Unlock()
	for i, mmap := range ps.Mmaps {
		if mmap.BaseAddress == addr {
			ps.Mmaps = slices.Delete(ps.Mmaps, i, i+1)
			return true
		}
	}
	return false
}

// FindMmap returns the memory mapping by the given address. The returned mapping is a copy.
func (ps *PS) FindMmap(addr va.Address) *Mmap {
	ps.RLock()
	defer ps.RUnlock()
	for i := range ps.Mmaps {
		if ps.Mmaps[i].BaseAddress == addr {
			mmap := ps.Mmaps[i]
			return &mmap
		}
	}
	return nil
}

// findModuleByAddr is the lock-free variant of FindModuleByAddr.
// The caller must hold the lock, and must not retain the pointer
// beyond the critical section.
func (ps *PS) findModuleByAddr(addr va.Address) *Module {
	for i := range ps.Modules {
		if ps.Modules[i].BaseAddress == addr {
			return &ps.Modules[i]
		}
	}
	return nil
}

var queryLiveModules = func(pid uint32) []sys.ProcessModule {
	return sys.EnumProcessModules(pid)
}

// FindModuleByVa finds the module name by probing the range of the given
// virtual address. The returned module is a copy.
func (ps *PS) FindModuleByVa(addr va.Address) *Module {
	ps.RLock()
	if m := ps.findModuleByVa(addr); m != nil {
		mod := *m
		ps.RUnlock()
		return &mod
	}
	ps.RUnlock()

	ps.onceMods.Do(func() {
		// query live process modules
		ps.modules = queryLiveModules(ps.PID)
	})

	// try to find the module within the VA space
	// and if found, add it to process modules for
	// future lookups
	for _, m := range ps.modules {
		b := va.Address(m.BaseOfDll)
		size := uint64(m.SizeOfImage)

		if addr < b || addr >= b.Inc(size) {
			continue
		}
		mod := Module{
			Name:               m.Name,
			BaseAddress:        b,
			Size:               size,
			DefaultBaseAddress: b,
		}

		ps.Lock()
		// another goroutine may have added the module in the meantime
		if existing := ps.findModuleByAddr(b); existing != nil {
			mod = *existing
		} else {
			ps.Modules = append(ps.Modules, mod)
		}
		ps.Unlock()

		return &mod
	}

	return nil
}

func (ps *PS) findModuleByVa(addr va.Address) *Module {
	for i := range ps.Modules {
		end := ps.Modules[i].BaseAddress.Inc(ps.Modules[i].Size)
		if addr >= ps.Modules[i].BaseAddress && addr < end {
			mod := &ps.Modules[i]
			return mod
		}
	}
	return nil
}
