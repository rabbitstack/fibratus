/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package va

import (
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"golang.org/x/sys/windows"
	"golang.org/x/time/rate"
	"strconv"
	"sync"
	"unsafe"
)

const (
	// MemImage indicates that the memory pages within the region are mapped
	// into the view of an image section.
	MemImage uint32 = 0x1000000
	// MemMapped indicates that the memory pages within the region are mapped
	// into the view of a section.
	MemMapped uint32 = 0x40000
	// MemPrivate Indicates that the memory pages within the region are private
	// that is, not shared by other processes.
	MemPrivate uint32 = 0x20000
)

const (
	// SectionData indicates a mapped view of a data file.
	SectionData = 0x0
	// SectionImage indicates a mapped view of an executable image.
	SectionImage = 0x4
	// SectionImageNoExecute indicates a mapped view an executable image file that will not be executed.
	SectionImageNoExecute = 0x8
	// SectionPagefile indicates a mapped view of pagefile-backed section.
	SectionPagefile = 0xC
	// SectionPhysical indicates that the allocation is a view of the \Device\PhysicalMemory section.
	SectionPhysical = 0xD
)

// RegionInfo  describes the allocated region page properties.
type RegionInfo struct {
	Type     uint32
	Protect  uint32
	BaseAddr uint64
	proc     windows.Handle
}

// IsMapped determines if the region is backed by the section object.
func (r RegionInfo) IsMapped() bool {
	return r.Type == MemImage || r.Type == MemMapped
}

// GetMappedFile checks whether the specified address is within
// a memory-mapped file in the address space of the specified process.
// If so, it returns the name of the memory-mapped file.
func (r RegionInfo) GetMappedFile() string {
	return sys.GetMappedFile(r.proc, uintptr(r.BaseAddr))
}

// ProtectMask returns protection in mask notation.
func (r RegionInfo) ProtectMask() string {
	switch r.Protect {
	case windows.PAGE_READONLY:
		return "R"
	case windows.PAGE_READWRITE:
		return "RW"
	case windows.PAGE_EXECUTE_READ:
		return "RX"
	case windows.PAGE_EXECUTE_READWRITE:
		return "RWX"
	case windows.PAGE_EXECUTE_WRITECOPY:
		return "RWXC"
	case windows.PAGE_EXECUTE:
		return "X"
	case windows.PAGE_WRITECOPY:
		return "WC"
	case windows.PAGE_NOACCESS:
		return "NA"
	case windows.PAGE_WRITECOMBINE:
		return "WCB"
	case windows.PAGE_GUARD, windows.PAGE_GUARD | windows.PAGE_READWRITE:
		return "PG"
	case windows.PAGE_NOCACHE:
		return "NC"
	case 0:
		return "-"
	default:
		return "?"
	}
}

// RegionProber examines metadata about the range of pages
// within the process virtual address space. It keeps the
// state of opened process handles for which VA spaces are
// consulted. To avoid noisy processes putting too much pressure
// on the `VirtualQueryEx` calls, the prober employs a set of
// limiters with token bucket strategy.
type RegionProber struct {
	// procs contains opened process handles for
	// which virtual address query was performed
	procs map[uint32]windows.Handle
	// lims contains token bucket limiters per pid
	lims map[uint32]*rate.Limiter
	mu   sync.Mutex
}

const (
	burst = 500 // limiter initial bucket size
	limit = 300 // rate of 300 region queries per second
)

// proberRateLimits accounts probe rate limits per process id
var proberRateLimits = expvar.NewMap("va.region.prober.rate.limits")

// NewRegionProber creates a fresh instance of the region prober.
func NewRegionProber() *RegionProber {
	return &RegionProber{procs: make(map[uint32]windows.Handle), lims: make(map[uint32]*rate.Limiter)}
}

// Query fetches region information for the specified process id and the
// base address. It keeps a cache of opened process handles and reuses
// them for subsequent calls to VirtualQueryEx. To defend against noisy
// processes, the throttling mechanism is implemented with token bucket
// limiters. If successful, this method returns the region info. Otherwise,
// it returns nil.
func (p *RegionProber) Query(pid uint32, addr uint64) *RegionInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	lim, ok := p.lims[pid]
	if !ok {
		lim = rate.NewLimiter(limit, burst)
		p.lims[pid] = lim
	}
	// check rate limit for the calling process
	if !lim.Allow() {
		proberRateLimits.Add(strconv.Itoa(int(pid)), 1)
		return nil
	}
	process, ok := p.procs[pid]
	if !ok {
		var err error
		process, err = windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
		if err != nil {
			return nil
		}
		p.procs[pid] = process
	}

	// query VA region info
	var mem windows.MemoryBasicInformation
	err := windows.VirtualQueryEx(process, uintptr(addr), &mem, unsafe.Sizeof(mem))
	if err != nil {
		return nil
	}

	return &RegionInfo{
		Type:     mem.Type,
		Protect:  mem.AllocationProtect,
		BaseAddr: addr,
		proc:     process,
	}
}

// Remove removes the process handle from cache and closes it.
// It returns true if the handle was closed successfully.
func (p *RegionProber) Remove(pid uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	process, ok := p.procs[pid]
	if !ok {
		return false
	}
	delete(p.procs, pid)
	delete(p.lims, pid)
	return windows.Close(process) == nil
}

// Close closes all opened process handles.
func (p *RegionProber) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, process := range p.procs {
		windows.Close(process)
	}
}

// Region describes the state of a range of pages in the
// process virtual address space and offers convenient
// methods for reading and accessing region memory.
// This code is inspired by libpeconv library:
// https://github.com/hasherezade/libpeconv
type Region struct {
	base    uintptr        // base address of the region of pages
	size    uintptr        // size of the region in bytes beginning at the base address
	typ     uint32         // type of pages in the region
	state   uint32         // state of the pages in the region
	protect uint32         // access protection of the pages in the region
	process windows.Handle // process handle for which the region is read
}

// ReadArea reads a full memory area within a given process, starting at the base
// address and reading up to the buffer size.
// The memory area can consist of multiple regions with various access rights.
// If the region is inaccessible and protection changing flag is enabled,
// this function tries to change the region protection to read-only access.
// If the request to change region protection is granted, upon completion,
// the original access permissions are restored.
// On read failure the region is skipped, and the read is moving to the
// next one leaving in the output buffer an empty space of the region size.
func ReadArea(process windows.Handle, base uintptr, bufSize, minSize uint, forceAccess bool) []byte {
	if bufSize == 0 || base == 0 {
		return nil
	}
	i := uint(0)
	buf := make([]byte, 0)
	for i < bufSize {
		chunk := base + uintptr(i)
		region, err := NewRegion(process, chunk)
		fmt.Println(err)
		if err != nil {
			break
		}
		if region.Size(chunk) == 0 {
			break
		}
		n, b := region.Read(chunk, bufSize-i, minSize, forceAccess)
		if n == 0 {
			// skip the region that could not be read
			// and fill it with zeros of region size
			i += region.Size(chunk)
			zeros := make([]byte, region.Size(chunk))
			buf = append(buf, zeros...)
			continue
		}
		i += n
		buf = append(buf, b...)
	}
	return buf
}

// Zeroed determines if all bytes in the area are zeroed.
func Zeroed(area []byte) bool {
	for _, b := range area {
		if b != 0 {
			return false
		}
	}
	return true
}

// NewRegion creates a new region for the specified process and base address.
func NewRegion(process windows.Handle, base uintptr) (*Region, error) {
	var m windows.MemoryBasicInformation
	err := windows.VirtualQueryEx(process, base, &m, unsafe.Sizeof(m))
	if err != nil {
		return nil, err
	}
	r := &Region{
		process: process,
		typ:     m.Type,
		state:   m.State,
		protect: m.Protect,
		size:    m.RegionSize,
		base:    m.BaseAddress,
	}
	return r, nil
}

// Size returns the size of the region starting from the base address.
func (r Region) Size(base uintptr) uint {
	if r.typ == 0 { // ignore invalid type
		return 0
	}
	if r.size > base {
		return 0
	}
	offset := base - r.base
	return uint(r.size - offset)
}

// Read reads a single memory region within a given process
// starting at supplied base address. In case region is inaccessible
// and the force access flag is enabled, it tries to force the access
// by temporarily changing the permissions of the memory region.
func (r Region) Read(addr uintptr, bufSize, minSize uint, forceAccess bool) (uint, []byte) {
	if bufSize == 0 {
		return 0, nil
	}
	if r.state&windows.MEM_COMMIT == 0 {
		// no committed pages in the region
		return 0, nil
	}
	if r.Size(addr) == 0 {
		return 0, nil
	}
	// size to read
	size := r.Size(addr)
	if size > bufSize {
		size = bufSize
	}
	var prevProtection uint32
	isAccessChanged := false
	isAccessible := r.protect&windows.PAGE_NOACCESS == 0
	if forceAccess && !isAccessible {
		// change page access right
		err := windows.VirtualProtectEx(r.process, addr, uintptr(r.Size(addr)), windows.PAGE_READONLY, &prevProtection)
		if err == nil {
			isAccessChanged = true
		}
		defer func() {
			// restore page access right
			if isAccessChanged {
				_ = windows.VirtualProtectEx(r.process, addr, uintptr(r.Size(addr)), prevProtection, &prevProtection)
			}
		}()
	}
	if isAccessible || isAccessChanged {
		n, b, err := r.read(addr, size, minSize)
		if n == 0 && (r.protect&windows.PAGE_GUARD) != 0 {
			// guarded page. Try to read again
			n, b, err = r.read(addr, size, minSize)
		}
		if n == 0 || err != nil {
			return 0, nil
		}
		return n, b
	}
	return 0, nil
}

// read allocates a buffer with maximum buffer size and attempts to
// read the memory chunk from the specified base address.
// If reading of the full buffer size was not possible, it will keep
// trying to read a smaller chunk, decreasing requested size on each
// attempt, until the minimal size is reached. This is a workaround for
// errors such as FAULTY_HARDWARE_CORRUPTED_PAGE. It returns how many
// bytes were successfully read, the memory buffer and an error in case
// of unrecoverable errors have occurred.
func (r Region) read(addr uintptr, bufSize, minSize uint) (uint, []byte, error) {
	size := uintptr(0)
	b := make([]byte, bufSize)
	err := windows.ReadProcessMemory(r.process, addr, &b[0], uintptr(bufSize), &size)
	if err == nil {
		// the entire memory chunk was read
		return uint(size), b, nil
	}
	if size == 0 && err != windows.ERROR_PARTIAL_COPY {
		// no data was read
		return 0, nil, err
	}
	if err == windows.ERROR_PARTIAL_COPY {
		// data partially read. Get readable size
		size = uintptr(r.seek(addr, b, bufSize, minSize))
	}
	if size > 0 {
		// have minimal readable size
		b = make([]byte, size)
		err := windows.ReadProcessMemory(r.process, addr, &b[0], size, &size)
		if err != nil {
			return 0, nil, err
		}
		return uint(size), b, nil
	}
	return 0, nil, nil
}

// seek performs a binary search via ReadProcessMemory, trying to find
// the biggest size of memory chunk within the buffer size that can be
// read. The search stops when the minimal size is reached. The given
// minimal size must be non-zero, and smaller than the buffer size.
func (r Region) seek(addr uintptr, buf []byte, bufSize, minSize uint) uint {
	if buf == nil || bufSize == 0 {
		return 0
	}
	if bufSize < minSize || minSize == 0 {
		return 0
	}
	size := uintptr(0)
	err := windows.ReadProcessMemory(r.process, addr, &buf[0], uintptr(minSize), &size)
	if err != nil {
		return uint(size)
	}
	n := bufSize / 2
	successSize := minSize
	failedSize := bufSize
	for n > minSize && n < bufSize {
		size = 0
		err := windows.ReadProcessMemory(r.process, addr, &buf[0], uintptr(n), &size)
		if err != nil {
			failedSize = n
		} else {
			successSize = n
		}
		delta := (failedSize - successSize) / 2
		if delta == 0 {
			break
		}
		n = delta + successSize
	}
	return successSize
}
