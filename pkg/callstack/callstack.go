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

package callstack

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/windows"
)

// unbacked represents the identifier for unbacked regions in stack frames
const unbacked = "unbacked"

var pageSize = uint64(os.Getpagesize())

// buildNumber stores the Windows OS build number
var _, _, buildNumber = windows.RtlGetNtVersionNumbers()

// Frame describes a single stack frame.
type Frame struct {
	PID           uint32     // pid owning thread's stack
	Addr          va.Address // return address
	Offset        uint64     // symbol offset
	Symbol        string     // symbol name
	Module        string     // module name
	ModuleAddress va.Address // module base address
}

// IsUnbacked returns true if this frame is originated
// from unbacked memory section
func (f Frame) IsUnbacked() bool { return f.Module == unbacked }

// AllocationSize calculates the private region size
// to which the frame return address pertains if the
// memory pages within the region are private and
// non-shareable pages.
func (f *Frame) AllocationSize(proc windows.Handle) uint64 {
	if f.Addr.InSystemRange() {
		return 0
	}

	r := va.VirtualQuery(proc, f.Addr.Uint64())

	if r == nil || (r.State != windows.MEM_COMMIT || r.Protect == windows.PAGE_NOACCESS || r.Type != va.MemImage) {
		return 0
	}

	var size uint64

	// traverse all pages in the region
	for n := uint64(0); n < r.Size; n += pageSize {
		addr := f.Addr.Inc(n)
		ws := va.QueryWorkingSet(proc, addr.Uint64())
		if ws == nil || !ws.Valid() {
			continue
		}

		// use SharedOriginal after RS3/1709
		if buildNumber >= 16299 {
			if !ws.SharedOriginal() {
				size += pageSize
			}
		} else {
			if !ws.Shared() {
				size += pageSize
			}
		}
	}

	return size
}

// Protection resolves the memory protection
// of the pages within the region that contains the
// frame return address.
func (f *Frame) Protection(proc windows.Handle) string {
	if f.Addr.InSystemRange() {
		return ""
	}
	r := va.VirtualQuery(proc, f.Addr.Uint64())
	if r == nil {
		return "?"
	}
	return r.ProtectMask()
}

// CallsiteAssembly decodes the callsite trailing/leading
// bytes depending on the value of the `leading` argument.
// The resulting string contains the decoded x86 machine
// opcodes in Intel assembler syntax.
func (f *Frame) CallsiteAssembly(proc windows.Handle, leading bool) string {
	if f.Addr.InSystemRange() {
		return ""
	}

	size := uint(512)
	base := f.Addr.Uintptr()
	if leading {
		base -= uintptr(size)
	}

	buf := va.ReadArea(proc, base, size, size, false)
	if len(buf) == 0 || va.Zeroed(buf) {
		return ""
	}

	var b strings.Builder

	for i := 0; i < len(buf); {
		ins, err := x86asm.Decode(buf[i:], 64)
		if err != nil {
			return b.String()
		}
		b.WriteString(x86asm.IntelSyntax(ins, f.Addr.Uint64(), nil))
		b.WriteRune('|')
		i += ins.Len
	}

	return b.String()
}

// Callstack is a sequence of stack frames
// representing function executions.
type Callstack []Frame

// Init allocates the initial callstack capacity.
func (s *Callstack) Init(n int) {
	*s = make(Callstack, 0, n)
}

// PushFrame pushes a new from to the call stack.
func (s *Callstack) PushFrame(f Frame) {
	if f.Module == "" {
		f.Module = unbacked
	}
	*s = append(*s, f)
}

// FrameAt returns the stack frame at the specified index.
func (s *Callstack) FrameAt(i int) Frame {
	if i > len(*s)-1 {
		return Frame{}
	}
	return (*s)[i]
}

// Depth returns the number of frames in the call stack.
func (s *Callstack) Depth() int { return len(*s) }

// IsEmpty returns true if the callstack has no frames.
func (s *Callstack) IsEmpty() bool { return s.Depth() == 0 }

// FinalUserFrame returns the final frame that corresponds
// to the user code execution. That usually translates to
// the last frame before ntdll or kernel32 modules.
func (s *Callstack) FinalUserFrame() *Frame {
	if s.IsEmpty() {
		return nil
	}

	var n int
	for n = s.Depth() - 1; n > 0; n-- {
		f := (*s)[n]
		if f.Addr.InSystemRange() {
			continue
		}
		mod := filepath.Base(strings.ToLower(f.Module))
		if mod != "ntdll.dll" && mod != "kernel32.dll" && mod != "kernelbase.dll" {
			break
		}
	}

	if n >= 0 && n < s.Depth()-1 {
		return &(*s)[n]
	}

	return nil
}

// FinalUserspaceFrame returns the final userspace frame. This
// frame is typically backed by the ntdll module.
func (s *Callstack) FinalUserspaceFrame() *Frame {
	if s.IsEmpty() {
		return nil
	}

	for n := s.Depth() - 1; n > 0; n-- {
		f := (*s)[n]
		if f.Addr.InSystemRange() {
			continue
		}
		return &f
	}

	return nil
}

// FinalKernelFrame returns the final kernel space frame.
func (s *Callstack) FinalKernelFrame() *Frame {
	if s.IsEmpty() {
		return nil
	}
	return &(*s)[s.Depth()-1]
}

// Summary returns a sequence of non-repeated module names.
func (s Callstack) Summary() string {
	var b strings.Builder
	var prev string
	var removeSep bool

	for i := range s {
		frame := s[len(s)-i-1]
		if frame.Addr.InSystemRange() {
			continue
		}

		var n string
		if frame.IsUnbacked() {
			n = unbacked
		} else {
			n = filepath.Base(frame.Module)
		}

		if n == prev {
			if i == len(s)-1 {
				// last module equals to the previous
				// which renders redundant separator
				removeSep = true
			}
			continue
		}

		b.WriteString(n)
		if i != len(s)-1 {
			b.WriteRune('|')
		}
		prev = n
	}

	if removeSep {
		return strings.TrimSuffix(b.String(), "|")
	}

	return b.String()
}

func (s Callstack) String() string {
	var b strings.Builder

	for i := range s {
		frame := s[len(s)-i-1]
		b.WriteString("0x")
		b.WriteString(frame.Addr.String())
		b.WriteString(" ")

		if frame.Addr.InSystemRange() && frame.Module == unbacked {
			b.WriteString("?")
		} else {
			b.WriteString(frame.Module)
		}

		b.WriteRune('!')
		if frame.Symbol != "" && frame.Symbol != "?" {
			b.WriteString(frame.Symbol)
		} else {
			b.WriteRune('?')
		}

		if frame.Offset != 0 {
			b.WriteString("+0x")
			b.WriteString(strconv.FormatUint(frame.Offset, 16))
		}

		if i != len(s)-1 {
			b.WriteRune('|')
		}
	}
	return b.String()
}

// ContainsUnbacked returns true if there is a frame
// pertaining to the function call initiated from the
// unbacked memory section. This method only checks
// user space frames for such a condition.
func (s Callstack) ContainsUnbacked() bool {
	for _, frame := range s {
		if !frame.Addr.InSystemRange() && frame.IsUnbacked() {
			return true
		}
	}
	return false
}

// ContainsSymbol checks if the supplied symbol name is present in the callstack.
func (s Callstack) ContainsSymbol(sym string) bool {
	for _, frame := range s {
		if frame.Symbol == sym {
			return true
		}
	}
	return false
}

// Addresses returns stack retrun addresses.
func (s Callstack) Addresses() []string {
	addrs := make([]string, len(s))
	for i, frame := range s {
		addrs[i] = frame.Addr.String()
	}
	return addrs
}

// Modules returns all modules comprising the thread stack.
func (s Callstack) Modules() []string {
	mods := make([]string, len(s))
	for i, f := range s {
		mods[i] = f.Module
	}
	return mods
}

// Symbols returns all symbols comprising the call stack.
// Each symbol name is prefixed with the source module.
func (s Callstack) Symbols() []string {
	syms := make([]string, len(s))
	for i, f := range s {
		syms[i] = filepath.Base(f.Module) + "!" + f.Symbol
	}
	return syms
}

// AllocationSizes returns allocation size of each stack frame
// in terms of allocation/module private non-shareable pages.
func (s Callstack) AllocationSizes(pid uint32) []uint64 {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return nil
	}
	defer windows.Close(proc)
	sizes := make([]uint64, len(s))
	for i, f := range s {
		sizes[i] = f.AllocationSize(proc)
	}
	return sizes
}

// Protections returns page protection mask for every
// frame comprising the stack.
func (s Callstack) Protections(pid uint32) []string {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return nil
	}
	defer windows.Close(proc)
	prots := make([]string, len(s))
	for i, f := range s {
		prots[i] = f.Protection(proc)
	}
	return prots
}

// CallsiteInsns returns callsite assembly opcodes
// for leading/trailing bytes contained in each frame.
func (s Callstack) CallsiteInsns(pid uint32, leading bool) []string {
	proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil
	}
	defer windows.Close(proc)
	opcodes := make([]string, len(s))
	for i, f := range s {
		opcodes[i] = f.CallsiteAssembly(proc, leading)
	}
	return opcodes
}
