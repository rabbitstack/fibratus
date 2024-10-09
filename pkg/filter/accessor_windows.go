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

package filter

import (
	"errors"
	"expvar"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/network"
	psnap "github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/cmdline"
	"github.com/rabbitstack/fibratus/pkg/util/loldrivers"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"golang.org/x/sys/windows"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

var (
	// ErrPENil indicates the PE (Portable Executable) data is nil
	ErrPENil = errors.New("pe state is nil")
)

// signatureErrors counts signature check/verification errors
var signatureErrors = expvar.NewInt("image.signature.errors")

// certErrors counts certificate parse errors
var certErrors = expvar.NewInt("image.certificate.errors")

// GetAccessors initializes and returns all available accessors.
func GetAccessors() []Accessor {
	return []Accessor{
		newPSAccessor(nil),
		newPEAccessor(),
		newMemAccessor(),
		newDNSAccessor(),
		newFileAccessor(),
		newKevtAccessor(),
		newImageAccessor(),
		newThreadAccessor(),
		newHandleAccessor(),
		newNetworkAccessor(),
		newRegistryAccessor(),
	}
}

func getParentPs(kevt *kevent.Kevent) *pstypes.PS {
	if kevt.PS == nil {
		return nil
	}
	return kevt.PS.Parent
}

// psAccessor extracts process's state or event specific values.
type psAccessor struct {
	psnap psnap.Snapshotter
}

func (psAccessor) SetFields(fields []fields.Field) {}
func (psAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.PS != nil || kevt.Category == ktypes.Process
}

func newPSAccessor(psnap psnap.Snapshotter) Accessor { return &psAccessor{psnap: psnap} }

func (ps *psAccessor) Get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.PsPid:
		// the process id that is generating the event
		return kevt.PID, nil
	case fields.PsSiblingPid, fields.PsChildPid:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		// the id of a freshly created process. `kevt.PID` references the parent process
		return kevt.Kparams.GetPid()
	case fields.PsPpid:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Ppid, nil
	case fields.PsName:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Name, nil
	case fields.PsSiblingName, fields.PsChildName:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.ProcessName)
	case fields.PsComm, fields.PsCmdline:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Cmdline, nil
	case fields.PsSiblingComm, fields.PsChildCmdline:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.Cmdline)
	case fields.PsExe:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Exe, nil
	case fields.PsSiblingExe, fields.PsChildExe:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.Exe)
	case fields.PsArgs:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Args, nil
	case fields.PsSiblingArgs, fields.PsChildArgs:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		cmndline, err := kevt.Kparams.GetString(kparams.Cmdline)
		if err != nil {
			return nil, err
		}
		return cmdline.Split(cmndline), nil
	case fields.PsCwd:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Cwd, nil
	case fields.PsSID:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.SID, nil
	case fields.PsSiblingSID, fields.PsChildSID:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		sid, err := kevt.Kparams.GetSID()
		if err != nil {
			return nil, err
		}
		return sid.String(), nil
	case fields.PsSiblingDomain, fields.PsChildDomain:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.Domain)
	case fields.PsSiblingUsername, fields.PsChildUsername:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.Username)
	case fields.PsChildIsWOW64Field:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		return (kevt.Kparams.MustGetUint32(kparams.ProcessFlags) & kevent.PsWOW64) != 0, nil
	case fields.PsChildIsPackagedField:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		return (kevt.Kparams.MustGetUint32(kparams.ProcessFlags) & kevent.PsPackaged) != 0, nil
	case fields.PsChildIsProtectedField:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		return (kevt.Kparams.MustGetUint32(kparams.ProcessFlags) & kevent.PsProtected) != 0, nil
	case fields.PsIsWOW64Field:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsWOW64, nil
	case fields.PsIsPackagedField:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsPackaged, nil
	case fields.PsIsProtectedField:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsProtected, nil
	case fields.PsDomain:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Domain, nil
	case fields.PsUsername:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Username, nil
	case fields.PsSessionID:
		ps := kevt.PS
		if ps == nil {
			return nil, nil
		}
		return ps.SessionID, nil
	case fields.PsAccessMask:
		if kevt.Type != ktypes.OpenProcess {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.DesiredAccess)
	case fields.PsAccessMaskNames:
		if kevt.Type != ktypes.OpenProcess {
			return nil, nil
		}
		return kevt.GetFlagsAsSlice(kparams.DesiredAccess), nil
	case fields.PsAccessStatus:
		if kevt.Type != ktypes.OpenProcess {
			return nil, nil
		}
		return kevt.GetParamAsString(kparams.NTStatus), nil
	case fields.PsSiblingSessionID, fields.PsChildSessionID:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		return kevt.Kparams.GetUint32(kparams.SessionID)
	case fields.PsEnvs:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		envs := make([]string, 0, len(ps.Envs))
		for env := range ps.Envs {
			envs = append(envs, env)
		}
		return envs, nil
	case fields.PsModules:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		mods := make([]string, 0, len(ps.Modules))
		for _, m := range ps.Modules {
			mods = append(mods, filepath.Base(m.Name))
		}
		return mods, nil
	case fields.PsUUID:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.UUID(), nil
	case fields.PsParentUUID:
		ps := getParentPs(kevt)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.UUID(), nil
	case fields.PsChildUUID:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		// find child process in snapshotter
		pid, err := kevt.Kparams.GetPid()
		if err != nil {
			return nil, err
		}
		if ps.psnap == nil {
			return nil, nil
		}
		proc := ps.psnap.FindAndPut(pid)
		if proc == nil {
			return nil, ErrPsNil
		}
		return proc.UUID(), nil
	case fields.PsHandles:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		handles := make([]string, len(ps.Handles))
		for i, handle := range ps.Handles {
			handles[i] = handle.Name
		}
		return handles, nil
	case fields.PsHandleTypes:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		types := make([]string, len(ps.Handles))
		for i, handle := range ps.Handles {
			if types[i] == handle.Type {
				continue
			}
			types[i] = handle.Type
		}
		return types, nil
	case fields.PsParentPid:
		parent := getParentPs(kevt)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.PID, nil
	case fields.PsParentName:
		parent := getParentPs(kevt)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Name, nil
	case fields.PsParentComm, fields.PsParentCmdline:
		parent := getParentPs(kevt)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Cmdline, nil
	case fields.PsParentExe:
		parent := getParentPs(kevt)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Exe, nil
	case fields.PsParentArgs:
		parent := getParentPs(kevt)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Args, nil
	case fields.PsParentCwd:
		parent := getParentPs(kevt)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Cwd, nil
	case fields.PsParentSID:
		parent := getParentPs(kevt)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.SID, nil
	case fields.PsParentDomain:
		ps := getParentPs(kevt)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Domain, nil
	case fields.PsParentUsername:
		ps := getParentPs(kevt)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Username, nil
	case fields.PsParentSessionID:
		ps := getParentPs(kevt)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.SessionID, nil
	case fields.PsParentEnvs:
		ps := getParentPs(kevt)
		if ps == nil {
			return nil, ErrPsNil
		}
		envs := make([]string, 0, len(ps.Envs))
		for env := range ps.Envs {
			envs = append(envs, env)
		}
		return envs, nil
	case fields.PsParentHandles:
		ps := getParentPs(kevt)
		if ps == nil {
			return nil, ErrPsNil
		}
		handles := make([]string, len(ps.Handles))
		for i, handle := range ps.Handles {
			handles[i] = handle.Name
		}
		return handles, nil
	case fields.PsParentHandleTypes:
		ps := getParentPs(kevt)
		if ps == nil {
			return nil, ErrPsNil
		}
		types := make([]string, len(ps.Handles))
		for i, handle := range ps.Handles {
			if types[i] == handle.Type {
				continue
			}
			types[i] = handle.Type
		}
		return types, nil
	case fields.PsParentIsWOW64Field:
		ps := getParentPs(kevt)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsWOW64, nil
	case fields.PsParentIsPackagedField:
		ps := getParentPs(kevt)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsPackaged, nil
	case fields.PsParentIsProtectedField:
		ps := getParentPs(kevt)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsProtected, nil
	default:
		switch {
		case f.IsEnvsMap():
			// access the specific environment variable
			env, _ := captureInBrackets(f.String())
			ps := kevt.PS
			if ps == nil {
				return nil, ErrPsNil
			}
			v, ok := ps.Envs[env]
			if ok {
				return v, nil
			}
			// match on prefix
			for k, v := range ps.Envs {
				if strings.HasPrefix(k, env) {
					return v, nil
				}
			}
		case f.IsModsMap():
			name, segment := captureInBrackets(f.String())
			ps := kevt.PS
			if ps == nil {
				return nil, ErrPsNil
			}
			mod := ps.FindModule(name)
			if mod == nil {
				return nil, nil
			}

			switch segment {
			case fields.ModuleSize:
				return mod.Size, nil
			case fields.ModuleChecksum:
				return mod.Checksum, nil
			case fields.ModuleBaseAddress:
				return mod.BaseAddress.String(), nil
			case fields.ModuleDefaultAddress:
				return mod.DefaultBaseAddress.String(), nil
			case fields.ModuleLocation:
				return filepath.Dir(mod.Name), nil
			}
		case f.IsAncestorMap():
			return ancestorFields(f.String(), kevt)
		}

		return nil, nil
	}
}

const (
	rootAncestor = "root"   // represents the root ancestor
	anyAncestor  = "any"    // represents any ancestor in the hierarchy
	frameUEnd    = "uend"   // represents the last user space stack frame
	frameUStart  = "ustart" // represents the first user space stack frame
	frameKEnd    = "kend"   // represents the last kernel space stack frame
	frameKStart  = "kstart" // represents the first kernel space stack frame
)

// ancestorFields recursively walks the process ancestors and extracts
// the required field values. If we get the `root` key, the root ancestor
// fields are inspected, while `any` accumulates values of all ancestors.
// Alternatively, the key may represent the depth that only returns the
// ancestor located at the given depth, starting with 1 which is the immediate
// process parent.
func ancestorFields(field string, kevt *kevent.Kevent) (kparams.Value, error) {
	key, segment := captureInBrackets(field)
	if key == "" || segment == "" {
		return nil, nil
	}

	var ps *pstypes.PS

	switch key {
	case rootAncestor:
		walk := func(proc *pstypes.PS) {
			ps = proc
		}
		pstypes.Walk(walk, kevt.PS)
	case anyAncestor:
		values := make([]string, 0)
		walk := func(proc *pstypes.PS) {
			switch segment {
			case fields.ProcessName:
				values = append(values, proc.Name)
			case fields.ProcessID:
				values = append(values, strconv.Itoa(int(proc.PID)))
			case fields.ProcessSID:
				values = append(values, proc.SID)
			case fields.ProcessSessionID:
				values = append(values, strconv.Itoa(int(proc.SessionID)))
			case fields.ProcessCwd:
				values = append(values, proc.Cwd)
			case fields.ProcessCmdline:
				values = append(values, proc.Cmdline)
			case fields.ProcessArgs:
				values = append(values, proc.Args...)
			case fields.ProcessExe:
				values = append(values, proc.Exe)
			}
		}
		pstypes.Walk(walk, kevt.PS)
		return values, nil
	default:
		depth, err := strconv.Atoi(key)
		if err != nil {
			return nil, err
		}
		var i int
		walk := func(proc *pstypes.PS) {
			i++
			if i == depth {
				ps = proc
			}
		}
		pstypes.Walk(walk, kevt.PS)
	}

	if ps == nil {
		return nil, nil
	}

	switch segment {
	case fields.ProcessName:
		return ps.Name, nil
	case fields.ProcessID:
		return ps.PID, nil
	case fields.ProcessSID:
		return ps.SID, nil
	case fields.ProcessSessionID:
		return ps.SessionID, nil
	case fields.ProcessCwd:
		return ps.Cwd, nil
	case fields.ProcessCmdline:
		return ps.Cmdline, nil
	case fields.ProcessArgs:
		return ps.Args, nil
	case fields.ProcessExe:
		return ps.Exe, nil
	}

	return nil, nil
}

// threadAccessor fetches thread parameters from thread events.
type threadAccessor struct{}

func (threadAccessor) SetFields(fields []fields.Field) {}
func (threadAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return !kevt.Callstack.IsEmpty() || kevt.Category == ktypes.Thread
}

func newThreadAccessor() Accessor {
	return &threadAccessor{}
}

func (t *threadAccessor) Get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.ThreadBasePrio:
		return kevt.Kparams.GetUint8(kparams.BasePrio)
	case fields.ThreadIOPrio:
		return kevt.Kparams.GetUint8(kparams.IOPrio)
	case fields.ThreadPagePrio:
		return kevt.Kparams.GetUint8(kparams.PagePrio)
	case fields.ThreadKstackBase:
		return kevt.GetParamAsString(kparams.KstackBase), nil
	case fields.ThreadKstackLimit:
		return kevt.GetParamAsString(kparams.KstackLimit), nil
	case fields.ThreadUstackBase:
		return kevt.GetParamAsString(kparams.UstackBase), nil
	case fields.ThreadUstackLimit:
		return kevt.GetParamAsString(kparams.UstackLimit), nil
	case fields.ThreadEntrypoint, fields.ThreadStartAddress:
		return kevt.GetParamAsString(kparams.StartAddress), nil
	case fields.ThreadPID:
		return kevt.Kparams.GetUint32(kparams.ProcessID)
	case fields.ThreadAccessMask:
		if kevt.Type != ktypes.OpenThread {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.DesiredAccess)
	case fields.ThreadAccessMaskNames:
		if kevt.Type != ktypes.OpenThread {
			return nil, nil
		}
		return kevt.GetFlagsAsSlice(kparams.DesiredAccess), nil
	case fields.ThreadAccessStatus:
		if kevt.Type != ktypes.OpenThread {
			return nil, nil
		}
		return kevt.GetParamAsString(kparams.NTStatus), nil
	case fields.ThreadCallstackSummary:
		return kevt.Callstack.Summary(), nil
	case fields.ThreadCallstackDetail:
		return kevt.Callstack.String(), nil
	case fields.ThreadCallstackModules:
		return kevt.Callstack.Modules(), nil
	case fields.ThreadCallstackSymbols:
		return kevt.Callstack.Symbols(), nil
	case fields.ThreadCallstackAllocationSizes:
		return kevt.Callstack.AllocationSizes(kevt.PID), nil
	case fields.ThreadCallstackProtections:
		return kevt.Callstack.Protections(kevt.PID), nil
	case fields.ThreadCallstackCallsiteLeadingAssembly:
		return kevt.Callstack.CallsiteInsns(kevt.PID, true), nil
	case fields.ThreadCallstackCallsiteTrailingAssembly:
		return kevt.Callstack.CallsiteInsns(kevt.PID, false), nil
	case fields.ThreadCallstackIsUnbacked:
		return kevt.Callstack.ContainsUnbacked(), nil
	default:
		if f.IsCallstackMap() {
			return callstackFields(f.String(), kevt)
		}
	}
	return nil, nil
}

// callstackFields is responsible for extracting
// the stack frame data for the specified frame
// index. The index 0 represents the least-recent
// frame, usually the base thread initialization
// frames.
func callstackFields(field string, kevt *kevent.Kevent) (kparams.Value, error) {
	if kevt.Callstack.IsEmpty() {
		return nil, nil
	}
	key, segment := captureInBrackets(field)
	if key == "" || segment == "" {
		return nil, nil
	}
	var i int
	switch key {
	case frameUStart:
		i = 0
	case frameUEnd:
		for ; i < kevt.Callstack.Depth()-1 && !kevt.Callstack[i].Addr.InSystemRange(); i++ {
		}
		i--
	case frameKStart:
		for i = kevt.Callstack.Depth() - 1; i >= 0 && kevt.Callstack[i].Addr.InSystemRange(); i-- {
		}
		i++
	case frameKEnd:
		i = kevt.Callstack.Depth() - 1
	default:
		if strings.HasSuffix(key, ".dll") {
			for n, frame := range kevt.Callstack {
				if strings.EqualFold(filepath.Base(frame.Module), key) {
					i = n
					break
				}
			}
		} else {
			var err error
			i, err = strconv.Atoi(key)
			if err != nil {
				return nil, err
			}
		}
	}

	if i > kevt.Callstack.Depth() || i < 0 {
		i = 0
	}
	f := kevt.Callstack[i]

	switch segment {
	case fields.FrameAddress:
		return f.Addr.String(), nil
	case fields.FrameSymbolOffset:
		return f.Offset, nil
	case fields.FrameModule:
		return f.Module, nil
	case fields.FrameSymbol:
		return f.Symbol, nil
	case fields.FrameProtection, fields.FrameAllocationSize:
		proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, kevt.PID)
		if err != nil {
			return nil, err
		}
		defer windows.Close(proc)
		if segment == fields.FrameProtection {
			return f.Protection(proc), nil
		}
		return f.AllocationSize(proc), nil
	case fields.FrameCallsiteLeadingAssembly, fields.FrameCallsiteTrailingAssembly:
		proc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, kevt.PID)
		if err != nil {
			return nil, err
		}
		defer windows.Close(proc)
		if segment == fields.FrameCallsiteLeadingAssembly {
			return f.CallsiteAssembly(proc, true), nil
		}
		return f.CallsiteAssembly(proc, false), nil
	case fields.FrameIsUnbacked:
		return f.IsUnbacked(), nil
	}
	return nil, nil
}

// fileAccessor extracts file specific values.
type fileAccessor struct{}

func (fileAccessor) SetFields(fields []fields.Field) {
	initLOLDriversClient(fields)
}
func (fileAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool { return kevt.Category == ktypes.File }

func newFileAccessor() Accessor {
	return &fileAccessor{}
}

func (l *fileAccessor) Get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.FileName:
		return kevt.GetParamAsString(kparams.FileName), nil
	case fields.FileOffset:
		return kevt.Kparams.GetUint64(kparams.FileOffset)
	case fields.FileIOSize:
		return kevt.Kparams.GetUint32(kparams.FileIoSize)
	case fields.FileShareMask:
		return kevt.GetParamAsString(kparams.FileShareMask), nil
	case fields.FileOperation:
		return kevt.GetParamAsString(kparams.FileOperation), nil
	case fields.FileObject:
		return kevt.Kparams.GetUint64(kparams.FileObject)
	case fields.FileType:
		return kevt.GetParamAsString(kparams.FileType), nil
	case fields.FileExtension:
		return filepath.Ext(kevt.GetParamAsString(kparams.FileName)), nil
	case fields.FileAttributes:
		return kevt.GetFlagsAsSlice(kparams.FileAttributes), nil
	case fields.FileStatus:
		if kevt.Type != ktypes.CreateFile {
			return nil, nil
		}
		return kevt.GetParamAsString(kparams.NTStatus), nil
	case fields.FileViewBase:
		return kevt.GetParamAsString(kparams.FileViewBase), nil
	case fields.FileViewSize:
		return kevt.Kparams.GetUint64(kparams.FileViewSize)
	case fields.FileViewType:
		return kevt.GetParamAsString(kparams.FileViewSectionType), nil
	case fields.FileViewProtection:
		return kevt.GetParamAsString(kparams.MemProtect), nil
	case fields.FileIsDriverVulnerable, fields.FileIsDriverMalicious:
		if kevt.IsCreateDisposition() && kevt.IsSuccess() {
			return isLOLDriver(f, kevt)
		}
		return false, nil
	case fields.FileIsDLL:
		return kevt.Kparams.GetBool(kparams.FileIsDLL)
	case fields.FileIsDriver:
		return kevt.Kparams.GetBool(kparams.FileIsDriver)
	case fields.FileIsExecutable:
		return kevt.Kparams.GetBool(kparams.FileIsExecutable)
	case fields.FilePID:
		return kevt.Kparams.GetPid()
	case fields.FileKey:
		return kevt.Kparams.GetUint64(kparams.FileKey)
	}
	return nil, nil
}

// imageAccessor extracts image (DLL, executable, driver) event values.
type imageAccessor struct{}

func (imageAccessor) SetFields(fields []fields.Field) {
	initLOLDriversClient(fields)
}
func (imageAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.Category == ktypes.Image
}

func newImageAccessor() Accessor {
	return &imageAccessor{}
}

func (i *imageAccessor) Get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	if kevt.IsLoadImage() && (f == fields.ImageSignatureType || f == fields.ImageSignatureLevel || f.IsImageCert()) {
		filename := kevt.GetParamAsString(kparams.FileName)
		addr := kevt.Kparams.MustGetUint64(kparams.ImageBase)
		typ := kevt.Kparams.MustGetUint32(kparams.ImageSignatureType)
		level := kevt.Kparams.MustGetUint32(kparams.ImageSignatureLevel)

		sign := signature.GetSignatures().GetSignature(addr)

		// signature already checked
		if typ != signature.None {
			if sign == nil {
				sign = &signature.Signature{
					Type:     typ,
					Level:    level,
					Filename: filename,
				}
			}
			if f.IsImageCert() {
				err := sign.ParseCertificate()
				if err != nil {
					certErrors.Add(1)
				}
			}
			signature.GetSignatures().PutSignature(addr, sign)
		} else {
			// image signature parameters exhibit unreliable behaviour. Allegedly,
			// signature verification is not performed in certain circumstances
			// which leads to the core system DLL or binaries to be reported with
			// signature unchecked level.
			// To mitigate this situation, we have to manually check/verify the
			// signature for all unchecked signature levels.
			if sign == nil {
				var err error
				sign = &signature.Signature{Filename: filename}
				sign.Type, sign.Level, err = sign.Check()
				if err != nil {
					signatureErrors.Add(1)
				}
				if sign.IsSigned() {
					sign.Verify()
				}
				if f.IsImageCert() {
					err := sign.ParseCertificate()
					if err != nil {
						certErrors.Add(1)
					}
				}
				signature.GetSignatures().PutSignature(addr, sign)
			}
			// reset signature type/level parameters
			_ = kevt.Kparams.SetValue(kparams.ImageSignatureType, sign.Type)
			_ = kevt.Kparams.SetValue(kparams.ImageSignatureLevel, sign.Level)
		}

		// append certificate parameters
		if sign.HasCertificate() {
			kevt.AppendParam(kparams.ImageCertIssuer, kparams.UnicodeString, sign.Cert.Issuer)
			kevt.AppendParam(kparams.ImageCertSubject, kparams.UnicodeString, sign.Cert.Subject)
			kevt.AppendParam(kparams.ImageCertSerial, kparams.UnicodeString, sign.Cert.SerialNumber)
			kevt.AppendParam(kparams.ImageCertNotAfter, kparams.Time, sign.Cert.NotAfter)
			kevt.AppendParam(kparams.ImageCertNotBefore, kparams.Time, sign.Cert.NotBefore)
		}
	}

	switch f {
	case fields.ImageName:
		return kevt.GetParamAsString(kparams.ImageFilename), nil
	case fields.ImageDefaultAddress:
		return kevt.GetParamAsString(kparams.ImageDefaultBase), nil
	case fields.ImageBase:
		return kevt.GetParamAsString(kparams.ImageBase), nil
	case fields.ImageSize:
		return kevt.Kparams.GetUint64(kparams.ImageSize)
	case fields.ImageChecksum:
		return kevt.Kparams.GetUint32(kparams.ImageCheckSum)
	case fields.ImagePID:
		return kevt.Kparams.GetPid()
	case fields.ImageSignatureType:
		return kevt.GetParamAsString(kparams.ImageSignatureType), nil
	case fields.ImageSignatureLevel:
		return kevt.GetParamAsString(kparams.ImageSignatureLevel), nil
	case fields.ImageCertSubject:
		return kevt.GetParamAsString(kparams.ImageCertSubject), nil
	case fields.ImageCertIssuer:
		return kevt.GetParamAsString(kparams.ImageCertIssuer), nil
	case fields.ImageCertSerial:
		return kevt.GetParamAsString(kparams.ImageCertSerial), nil
	case fields.ImageCertBefore:
		return kevt.Kparams.GetTime(kparams.ImageCertNotBefore)
	case fields.ImageCertAfter:
		return kevt.Kparams.GetTime(kparams.ImageCertNotAfter)
	case fields.ImageIsDriverVulnerable, fields.ImageIsDriverMalicious:
		if kevt.IsLoadImage() {
			return isLOLDriver(f, kevt)
		}
		return false, nil
	case fields.ImageIsDLL:
		return kevt.Kparams.GetBool(kparams.FileIsDLL)
	case fields.ImageIsDriver:
		return kevt.Kparams.GetBool(kparams.FileIsDriver)
	case fields.ImageIsExecutable:
		return kevt.Kparams.GetBool(kparams.FileIsExecutable)
	case fields.ImageIsDotnet:
		p, err := pe.ParseFile(kevt.GetParamAsString(kparams.ImageFilename), pe.WithCLR())
		if err != nil {
			return nil, err
		}
		return p.IsDotnet, nil
	}
	return nil, nil
}

// registryAccessor extracts registry specific parameters.
type registryAccessor struct{}

func (registryAccessor) SetFields(fields []fields.Field) {}
func (registryAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.Category == ktypes.Registry
}

func newRegistryAccessor() Accessor {
	return &registryAccessor{}
}

func (r *registryAccessor) Get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.RegistryKeyName:
		return kevt.GetParamAsString(kparams.RegKeyName), nil
	case fields.RegistryKeyHandle:
		return kevt.GetParamAsString(kparams.RegKeyHandle), nil
	case fields.RegistryValue:
		return kevt.Kparams.GetRaw(kparams.RegValue)
	case fields.RegistryValueType:
		return kevt.Kparams.GetString(kparams.RegValueType)
	case fields.RegistryStatus:
		return kevt.GetParamAsString(kparams.NTStatus), nil
	}
	return nil, nil
}

// networkAccessor deals with extracting the network specific event parameters.
type networkAccessor struct {
	reverseDNS *network.ReverseDNS
}

func (n *networkAccessor) SetFields(flds []fields.Field) {
	for _, f := range flds {
		if f == fields.NetSIPNames || f == fields.NetDIPNames {
			n.reverseDNS = network.GetReverseDNS(2000, time.Minute*30, time.Minute*2)
			break
		}
	}
}

func (networkAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.Category == ktypes.Net
}

func newNetworkAccessor() Accessor { return &networkAccessor{} }

func (n *networkAccessor) Get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.NetDIP:
		return kevt.Kparams.GetIP(kparams.NetDIP)
	case fields.NetSIP:
		return kevt.Kparams.GetIP(kparams.NetSIP)
	case fields.NetDport:
		return kevt.Kparams.GetUint16(kparams.NetDport)
	case fields.NetSport:
		return kevt.Kparams.GetUint16(kparams.NetSport)
	case fields.NetDportName:
		return kevt.Kparams.GetString(kparams.NetDportName)
	case fields.NetSportName:
		return kevt.Kparams.GetString(kparams.NetSportName)
	case fields.NetL4Proto:
		return kevt.GetParamAsString(kparams.NetL4Proto), nil
	case fields.NetPacketSize:
		return kevt.Kparams.GetUint32(kparams.NetSize)
	case fields.NetDIPNames:
		return n.resolveNamesForIP(kevt.Kparams.MustGetIP(kparams.NetDIP))
	case fields.NetSIPNames:
		return n.resolveNamesForIP(kevt.Kparams.MustGetIP(kparams.NetSIP))
	}
	return nil, nil
}

func (n *networkAccessor) resolveNamesForIP(ip net.IP) ([]string, error) {
	if n.reverseDNS == nil {
		return nil, nil
	}
	names, err := n.reverseDNS.Add(network.AddressFromIP(ip))
	if err != nil {
		return nil, err
	}
	return names, nil
}

// handleAccessor extracts handle event values.
type handleAccessor struct{}

func (handleAccessor) SetFields(fields []fields.Field) {}
func (handleAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.Category == ktypes.Handle
}

func newHandleAccessor() Accessor { return &handleAccessor{} }

func (h *handleAccessor) Get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.HandleID:
		return kevt.Kparams.GetUint32(kparams.HandleID)
	case fields.HandleType:
		return kevt.GetParamAsString(kparams.HandleObjectTypeID), nil
	case fields.HandleName:
		return kevt.Kparams.GetString(kparams.HandleObjectName)
	case fields.HandleObject:
		return kevt.Kparams.GetUint64(kparams.HandleObject)
	}
	return nil, nil
}

// peAccessor extracts PE specific values.
type peAccessor struct {
	fields []fields.Field
}

func (pa *peAccessor) SetFields(fields []fields.Field) {
	pa.fields = fields
}
func (peAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.PS != nil || kevt.IsLoadImage()
}

// parserOpts traverses all fields declared in the expression and
// dynamically determines what aspects of the PE need to be parsed.
func (pa *peAccessor) parserOpts() []pe.Option {
	var opts []pe.Option
	for _, f := range pa.fields {
		if f.IsPeSection() || f.IsPeSectionsMap() || f.IsPeModified() {
			opts = append(opts, pe.WithSections())
		}
		if f.IsPeSymbol() {
			opts = append(opts, pe.WithSymbols())
		}
		if f.IsPeSectionEntropy() {
			opts = append(opts, pe.WithSections(), pe.WithSectionEntropy())
		}
		if f.IsPeVersionResource() || f.IsPeResourcesMap() {
			opts = append(opts, pe.WithVersionResources())
		}
		if f.IsPeImphash() {
			opts = append(opts, pe.WithImphash())
		}
		if f.IsPeDotnet() || f.IsPeModified() {
			opts = append(opts, pe.WithCLR())
		}
		if f.IsPeAnomalies() {
			opts = append(opts, pe.WithSections(), pe.WithSymbols())
		}
		if f.IsPeSignature() {
			opts = append(opts, pe.WithSecurity())
		}
	}
	return opts
}

// ErrPeNilCertificate indicates the PE certificate is not available
var ErrPeNilCertificate = errors.New("pe certificate is nil")

func newPEAccessor() Accessor {
	return &peAccessor{}
}

func (pa *peAccessor) Get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	var p *pe.PE
	if kevt.PS != nil && kevt.PS.PE != nil {
		p = kevt.PS.PE
	}

	// PE enrichment is likely disabled. Load PE data lazily
	// by only requesting parsing of the PE directories that
	// are relevant to the fields present in the expression.
	// If the field references a child process executable
	// original file name as part of the CreateProcess event,
	// then the parser obtains the PE metadata for the executable
	// path parameter
	if (kevt.PS != nil && kevt.PS.Exe != "" && p == nil) || f == fields.PePsChildFileName || f == fields.PsChildPeFilename {
		var err error
		var exe string
		if (f == fields.PePsChildFileName || f == fields.PsChildPeFilename) && kevt.IsCreateProcess() {
			exe = kevt.GetParamAsString(kparams.Exe)
		} else {
			exe = kevt.PS.Exe
		}
		p, err = pe.ParseFile(exe, pa.parserOpts()...)
		if err != nil {
			return nil, err
		}
	}

	// here we determine if the PE was tampered. This check
	// consists of two steps starting with parsing the disk
	// PE for loaded executables followed by fetching the PE
	// from process' memory at the base address of the loaded
	// executable image
	if kevt.IsLoadImage() && f.IsPeModified() {
		filename := kevt.GetParamAsString(kparams.FileName)
		isExecutable := filepath.Ext(filename) == ".exe" || kevt.Kparams.TryGetBool(kparams.FileIsExecutable)
		if !isExecutable {
			return nil, nil
		}

		pid := kevt.Kparams.MustGetPid()
		addr := kevt.Kparams.MustGetUint64(kparams.ImageBase)

		file, err := pe.ParseFile(filename, pa.parserOpts()...)
		if err != nil {
			return nil, err
		}
		mem, err := pe.ParseMem(pid, uintptr(addr), false, pa.parserOpts()...)
		if err != nil {
			return nil, err
		}
		isModified := file.IsHeaderModified(mem)
		if p != nil {
			p.IsModified = isModified
		}
		return isModified, nil
	}

	if p == nil {
		return nil, ErrPENil
	}

	// verify signature
	if f.IsPeSignature() {
		p.VerifySignature()
	}

	if f != fields.PePsChildFileName {
		kevt.PS.PE = p
	}

	switch f {
	case fields.PeEntrypoint:
		return p.EntryPoint, nil
	case fields.PeBaseAddress:
		return p.ImageBase, nil
	case fields.PeNumSections:
		return p.NumberOfSections, nil
	case fields.PeNumSymbols:
		return p.NumberOfSymbols, nil
	case fields.PeSymbols:
		return p.Symbols, nil
	case fields.PeImports:
		return p.Imports, nil
	case fields.PeImphash:
		return p.Imphash, nil
	case fields.PeIsDotnet:
		return p.IsDotnet, nil
	case fields.PeAnomalies:
		return p.Anomalies, nil
	case fields.PeIsSigned:
		return p.IsSigned, nil
	case fields.PeIsTrusted:
		return p.IsTrusted, nil
	case fields.PeIsModified:
		return p.IsModified, nil
	case fields.PeCertIssuer:
		if p.Cert == nil {
			return nil, ErrPeNilCertificate
		}
		return p.Cert.Issuer, nil
	case fields.PeCertSubject:
		if p.Cert == nil {
			return nil, ErrPeNilCertificate
		}
		return p.Cert.Subject, nil
	case fields.PeCertSerial:
		if p.Cert == nil {
			return nil, ErrPeNilCertificate
		}
		return p.Cert.SerialNumber, nil
	case fields.PeCertAfter:
		if p.Cert == nil {
			return nil, ErrPeNilCertificate
		}
		return p.Cert.NotAfter, nil
	case fields.PeCertBefore:
		if p.Cert == nil {
			return nil, ErrPeNilCertificate
		}
		return p.Cert.NotBefore, nil
	case fields.PeIsDLL:
		return kevt.Kparams.GetBool(kparams.FileIsDLL)
	case fields.PeIsDriver:
		return kevt.Kparams.GetBool(kparams.FileIsDriver)
	case fields.PeIsExecutable:
		return kevt.Kparams.GetBool(kparams.FileIsExecutable)
	case fields.PeCompany:
		return p.VersionResources[pe.Company], nil
	case fields.PeCopyright:
		return p.VersionResources[pe.LegalCopyright], nil
	case fields.PeDescription:
		return p.VersionResources[pe.FileDescription], nil
	case fields.PeFileName, fields.PePsChildFileName, fields.PsChildPeFilename:
		return p.VersionResources[pe.OriginalFilename], nil
	case fields.PeFileVersion:
		return p.VersionResources[pe.FileVersion], nil
	case fields.PeProduct:
		return p.VersionResources[pe.ProductName], nil
	case fields.PeProductVersion:
		return p.VersionResources[pe.ProductVersion], nil
	default:
		switch {
		case f.IsPeSectionsMap():
			// get the section name
			section, segment := captureInBrackets(f.String())
			sec := p.Section(section)
			if sec == nil {
				return nil, nil
			}
			switch segment {
			case fields.SectionEntropy:
				return sec.Entropy, nil
			case fields.SectionMD5Hash:
				return sec.Md5, nil
			case fields.SectionSize:
				return sec.Size, nil
			}
		case f.IsPeResourcesMap():
			// consult the resource name
			key, _ := captureInBrackets(f.String())
			v, ok := p.VersionResources[key]
			if ok {
				return v, nil
			}
			// match on prefix (e.g. pe.resources[Org] = Blackwater)
			for k, v := range p.VersionResources {
				if strings.HasPrefix(k, key) {
					return v, nil
				}
			}
		}
	}

	return nil, nil
}

// memAccessor extracts parameters from memory alloc/free events.
type memAccessor struct{}

func (memAccessor) SetFields(fields []fields.Field)            {}
func (memAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool { return kevt.Category == ktypes.Mem }

func newMemAccessor() Accessor {
	return &memAccessor{}
}

func (*memAccessor) Get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.MemPageType:
		return kevt.GetParamAsString(kparams.MemPageType), nil
	case fields.MemAllocType:
		return kevt.GetParamAsString(kparams.MemAllocType), nil
	case fields.MemProtection:
		return kevt.GetParamAsString(kparams.MemProtect), nil
	case fields.MemBaseAddress:
		return kevt.Kparams.GetUint64(kparams.MemBaseAddress)
	case fields.MemRegionSize:
		return kevt.Kparams.GetUint64(kparams.MemRegionSize)
	case fields.MemProtectionMask:
		return kevt.Kparams.GetString(kparams.MemProtectMask)
	}
	return nil, nil
}

// dnsAccessor extracts values from DNS query/response event parameters.
type dnsAccessor struct{}

func (dnsAccessor) SetFields(fields []fields.Field) {}
func (dnsAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.Type.Subcategory() == ktypes.DNS
}

func newDNSAccessor() Accessor {
	return &dnsAccessor{}
}

func (*dnsAccessor) Get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.DNSName:
		return kevt.GetParamAsString(kparams.DNSName), nil
	case fields.DNSRR:
		return kevt.GetParamAsString(kparams.DNSRR), nil
	case fields.DNSRcode:
		return kevt.GetParamAsString(kparams.DNSRcode), nil
	case fields.DNSOptions:
		return kevt.GetFlagsAsSlice(kparams.DNSOpts), nil
	case fields.DNSAnswers:
		return kevt.Kparams.GetSlice(kparams.DNSAnswers)
	}
	return nil, nil
}

func captureInBrackets(s string) (string, fields.Segment) {
	lbracket := strings.Index(s, "[")
	if lbracket == -1 {
		return "", ""
	}
	rbracket := strings.Index(s, "]")
	if rbracket == -1 {
		return "", ""
	}
	if lbracket+1 > len(s) {
		return "", ""
	}
	if rbracket+2 < len(s) {
		return s[lbracket+1 : rbracket], fields.Segment(s[rbracket+2:])
	}
	return s[lbracket+1 : rbracket], ""
}

// isLOLDriver interacts with the loldrivers client to determine
// whether the loaded/dropped driver is malicious or vulnerable.
func isLOLDriver(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	filename := kevt.GetParamAsString(kparams.FileName)
	isDriver := filepath.Ext(filename) == ".sys" || kevt.Kparams.TryGetBool(kparams.FileIsDriver)
	if !isDriver {
		return nil, nil
	}
	ok, driver := loldrivers.GetClient().MatchHash(filename)
	if !ok {
		return nil, nil
	}
	if (f == fields.FileIsDriverVulnerable || f == fields.ImageIsDriverVulnerable) && driver.IsVulnerable {
		return true, nil
	}
	if (f == fields.FileIsDriverMalicious || f == fields.ImageIsDriverMalicious) && driver.IsMalicious {
		return true, nil
	}
	return false, nil
}

// initLOLDriversClient initializes the loldrivers client if the filter expression
// contains any of the relevant fields.
func initLOLDriversClient(flds []fields.Field) {
	for _, f := range flds {
		if f == fields.FileIsDriverVulnerable || f == fields.FileIsDriverMalicious ||
			f == fields.ImageIsDriverVulnerable || f == fields.ImageIsDriverMalicious {
			loldrivers.InitClient(loldrivers.WithAsyncDownload())
		}
	}
}
