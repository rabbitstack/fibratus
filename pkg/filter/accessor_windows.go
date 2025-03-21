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
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/network"
	psnap "github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/cmdline"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
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
		newThreadpoolAccessor(),
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

func (psAccessor) SetFields([]Field)            {}
func (psAccessor) SetSegments([]fields.Segment) {}
func (psAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.PS != nil || kevt.Category == ktypes.Process
}

func newPSAccessor(psnap psnap.Snapshotter) Accessor { return &psAccessor{psnap: psnap} }

func (ps *psAccessor) Get(f Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f.Name {
	case fields.PsPid:
		// identifier of the process that is generating the event
		return kevt.PID, nil
	case fields.PsSiblingPid, fields.PsChildPid:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		// the id of a created child process. `kevt.PID` is the parent process id
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
	case fields.PsModuleNames:
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
	case fields.PsHandleNames:
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
		for k, v := range ps.Envs {
			envs = append(envs, k+":"+v)
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
	case fields.PsAncestors:
		if kevt.PS != nil {
			ancestors := make([]*pstypes.PS, 0)
			walk := func(proc *pstypes.PS) {
				ancestors = append(ancestors, proc)
			}
			pstypes.Walk(walk, kevt.PS)

			return ancestors, nil
		}
		return nil, ErrPsNil
	case fields.PsModules:
		if kevt.PS != nil {
			return kevt.PS.Modules, nil
		}
		return nil, ErrPsNil
	case fields.PsThreads:
		if kevt.PS != nil {
			return kevt.PS.Threads, nil
		}
		return nil, ErrPsNil
	case fields.PsMmaps:
		if kevt.PS != nil {
			return kevt.PS.Mmaps, nil
		}
		return nil, ErrPsNil
	case fields.PsAncestor:
		if kevt.PS != nil {
			n := -1
			// if the index is given try to parse it
			// to access the ancestor at the given level.
			// For example, ps.ancestor[0] would retrieve
			// the process parent, ps.ancestor[1] would
			// return the process grandparent and so on.
			if f.Arg != "" {
				var err error
				n, err = strconv.Atoi(f.Arg)
				if err != nil {
					return nil, err
				}
			}

			ancestors := make([]string, 0)
			walk := func(proc *pstypes.PS) {
				ancestors = append(ancestors, proc.Name)
			}
			pstypes.Walk(walk, kevt.PS)

			if n >= 0 {
				// return a single ancestor indicated by the index
				if n < len(ancestors) {
					return ancestors[n], nil
				} else {
					return "", nil
				}
			} else {
				// return all ancestors
				return ancestors, nil
			}
		}
		return nil, ErrPsNil
	case fields.PsEnvs:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		// resolve a single env variable indicated by the arg
		// For example, ps.envs[winroot] would return the value
		// of the winroot environment variable
		if f.Arg != "" {
			env := f.Arg
			v, ok := ps.Envs[env]
			if ok {
				return v, nil
			}

			// match on env variable name prefix
			for k, v := range ps.Envs {
				if strings.HasPrefix(k, env) {
					return v, nil
				}
			}
		} else {
			// return all environment variables as a string slice
			envs := make([]string, 0, len(ps.Envs))
			for k, v := range ps.Envs {
				envs = append(envs, k+":"+v)
			}
			return envs, nil
		}
	}

	return nil, nil
}

// threadAccessor fetches thread parameters from thread events.
type threadAccessor struct{}

func (threadAccessor) SetFields([]Field)            {}
func (threadAccessor) SetSegments([]fields.Segment) {}
func (threadAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return !kevt.Callstack.IsEmpty() || kevt.Category == ktypes.Thread
}

func newThreadAccessor() Accessor {
	return &threadAccessor{}
}

func (t *threadAccessor) Get(f Field, e *kevent.Kevent) (kparams.Value, error) {
	switch f.Name {
	case fields.ThreadBasePrio:
		return e.Kparams.GetUint8(kparams.BasePrio)
	case fields.ThreadIOPrio:
		return e.Kparams.GetUint8(kparams.IOPrio)
	case fields.ThreadPagePrio:
		return e.Kparams.GetUint8(kparams.PagePrio)
	case fields.ThreadKstackBase:
		return e.GetParamAsString(kparams.KstackBase), nil
	case fields.ThreadKstackLimit:
		return e.GetParamAsString(kparams.KstackLimit), nil
	case fields.ThreadUstackBase:
		return e.GetParamAsString(kparams.UstackBase), nil
	case fields.ThreadUstackLimit:
		return e.GetParamAsString(kparams.UstackLimit), nil
	case fields.ThreadEntrypoint, fields.ThreadStartAddress:
		return e.GetParamAsString(kparams.StartAddress), nil
	case fields.ThreadPID:
		return e.Kparams.GetUint32(kparams.ProcessID)
	case fields.ThreadTEB:
		return e.GetParamAsString(kparams.TEB), nil
	case fields.ThreadAccessMask:
		if e.Type != ktypes.OpenThread {
			return nil, nil
		}
		return e.Kparams.GetString(kparams.DesiredAccess)
	case fields.ThreadAccessMaskNames:
		if e.Type != ktypes.OpenThread {
			return nil, nil
		}
		return e.GetFlagsAsSlice(kparams.DesiredAccess), nil
	case fields.ThreadAccessStatus:
		if e.Type != ktypes.OpenThread {
			return nil, nil
		}
		return e.GetParamAsString(kparams.NTStatus), nil
	case fields.ThreadCallstackSummary:
		return e.Callstack.Summary(), nil
	case fields.ThreadCallstackDetail:
		return e.Callstack.String(), nil
	case fields.ThreadCallstackModules:
		// return the module at the given frame level
		if f.Arg != "" {
			n, err := strconv.Atoi(f.Arg)
			if err != nil {
				return nil, err
			}

			if n > e.Callstack.Depth() {
				return "", nil
			}

			return e.Callstack.FrameAt(n).Module, nil
		}

		return e.Callstack.Modules(), nil
	case fields.ThreadCallstackSymbols:
		// return the symbol at the given frame level
		if f.Arg != "" {
			n, err := strconv.Atoi(f.Arg)
			if err != nil {
				return nil, err
			}

			if n > e.Callstack.Depth() {
				return "", nil
			}

			return e.Callstack.FrameAt(n).Symbol, nil
		}

		return e.Callstack.Symbols(), nil
	case fields.ThreadCallstackAllocationSizes:
		return e.Callstack.AllocationSizes(e.PID), nil
	case fields.ThreadCallstackProtections:
		return e.Callstack.Protections(e.PID), nil
	case fields.ThreadCallstackCallsiteLeadingAssembly:
		return e.Callstack.CallsiteInsns(e.PID, true), nil
	case fields.ThreadCallstackCallsiteTrailingAssembly:
		return e.Callstack.CallsiteInsns(e.PID, false), nil
	case fields.ThreadCallstackIsUnbacked:
		return e.Callstack.ContainsUnbacked(), nil
	case fields.ThreadCallstack:
		return e.Callstack, nil
	case fields.ThreadStartAddressSymbol:
		if e.Type != ktypes.CreateThread {
			return nil, nil
		}
		return e.GetParamAsString(kparams.StartAddressSymbol), nil
	case fields.ThreadStartAddressModule:
		if e.Type != ktypes.CreateThread {
			return nil, nil
		}
		return e.GetParamAsString(kparams.StartAddressModule), nil
	case fields.ThreadCallstackAddresses:
		return e.Callstack.Addresses(), nil
	case fields.ThreadCallstackFinalUserModuleName, fields.ThreadCallstackFinalUserModulePath:
		frame := e.Callstack.FinalUserFrame()
		if frame != nil {
			if f.Name == fields.ThreadCallstackFinalUserModuleName {
				return filepath.Base(frame.Module), nil
			}
			return frame.Module, nil
		}
		return nil, nil
	case fields.ThreadCallstackFinalUserSymbolName:
		frame := e.Callstack.FinalUserFrame()
		if frame != nil {
			return frame.Symbol, nil
		}
		return nil, nil
	case fields.ThreadCallstackFinalKernelModuleName, fields.ThreadCallstackFinalKernelModulePath:
		frame := e.Callstack.FinalKernelFrame()
		if frame != nil {
			if f.Name == fields.ThreadCallstackFinalKernelModuleName {
				return filepath.Base(frame.Module), nil
			}
			return frame.Module, nil
		}
		return nil, nil
	case fields.ThreadCallstackFinalKernelSymbolName:
		frame := e.Callstack.FinalKernelFrame()
		if frame != nil {
			return frame.Symbol, nil
		}
		return nil, nil
	case fields.ThreadCallstackFinalUserModuleSignatureIsSigned, fields.ThreadCallstackFinalUserModuleSignatureIsTrusted:
		frame := e.Callstack.FinalUserFrame()
		if frame == nil || (frame != nil && frame.ModuleAddress.IsZero()) {
			return nil, nil
		}

		sign := getSignature(frame.ModuleAddress, frame.Module, false)
		if sign == nil {
			return nil, nil
		}

		if f.Name == fields.ThreadCallstackFinalUserModuleSignatureIsSigned {
			return sign.IsSigned(), nil
		}

		return sign.IsTrusted(), nil
	case fields.ThreadCallstackFinalUserModuleSignatureCertIssuer, fields.ThreadCallstackFinalUserModuleSignatureCertSubject:
		frame := e.Callstack.FinalUserFrame()
		if frame == nil || (frame != nil && frame.ModuleAddress.IsZero()) {
			return nil, nil
		}

		sign := getSignature(frame.ModuleAddress, frame.Module, true)
		if sign == nil {
			return nil, nil
		}

		if sign.HasCertificate() && f.Name == fields.ThreadCallstackFinalUserModuleSignatureCertIssuer {
			return sign.Cert.Issuer, nil
		}

		if sign.HasCertificate() {
			return sign.Cert.Subject, nil
		}
	}

	return nil, nil
}

// fileAccessor extracts file specific values.
type fileAccessor struct{}

func (fileAccessor) SetFields(fields []Field) {
	initLOLDriversClient(fields)
}
func (fileAccessor) SetSegments([]fields.Segment) {}

func (fileAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool { return kevt.Category == ktypes.File }

func newFileAccessor() Accessor {
	return &fileAccessor{}
}

func (l *fileAccessor) Get(f Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f.Name {
	case fields.FilePath:
		return kevt.GetParamAsString(kparams.FilePath), nil
	case fields.FileName:
		return filepath.Base(kevt.GetParamAsString(kparams.FilePath)), nil
	case fields.FileExtension:
		return filepath.Ext(kevt.GetParamAsString(kparams.FilePath)), nil
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
			return isLOLDriver(f.Name, kevt)
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
	case fields.FileInfoClass:
		return kevt.GetParamAsString(kparams.FileInfoClass), nil
	case fields.FileInfoAllocationSize:
		if kevt.Kparams.TryGetUint32(kparams.FileInfoClass) == fs.AllocationClass {
			return kevt.Kparams.GetUint64(kparams.FileExtraInfo)
		}
	case fields.FileInfoEOFSize:
		if kevt.Kparams.TryGetUint32(kparams.FileInfoClass) == fs.EOFClass {
			return kevt.Kparams.GetUint64(kparams.FileExtraInfo)
		}
	case fields.FileInfoIsDispositionDeleteFile:
		return kevt.Kparams.TryGetUint32(kparams.FileInfoClass) == fs.DispositionClass &&
			kevt.Kparams.TryGetUint64(kparams.FileExtraInfo) > 0, nil
	}

	return nil, nil
}

// imageAccessor extracts image (DLL, executable, driver) event values.
type imageAccessor struct{}

func (imageAccessor) SetFields(fields []Field) {
	initLOLDriversClient(fields)
}
func (imageAccessor) SetSegments([]fields.Segment) {}

func (imageAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.Category == ktypes.Image
}

func newImageAccessor() Accessor {
	return &imageAccessor{}
}

func (i *imageAccessor) Get(f Field, kevt *kevent.Kevent) (kparams.Value, error) {
	if kevt.IsLoadImage() && (f.Name == fields.ImageSignatureType || f.Name == fields.ImageSignatureLevel || f.Name.IsImageCert()) {
		filename := kevt.GetParamAsString(kparams.ImagePath)
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
			if f.Name.IsImageCert() {
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
				if f.Name.IsImageCert() {
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

	switch f.Name {
	case fields.ImagePath:
		return kevt.GetParamAsString(kparams.ImagePath), nil
	case fields.ImageName:
		return filepath.Base(kevt.GetParamAsString(kparams.ImagePath)), nil
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
			return isLOLDriver(f.Name, kevt)
		}
		return false, nil
	case fields.ImageIsDLL:
		return kevt.Kparams.GetBool(kparams.FileIsDLL)
	case fields.ImageIsDriver:
		return kevt.Kparams.GetBool(kparams.FileIsDriver)
	case fields.ImageIsExecutable:
		return kevt.Kparams.GetBool(kparams.FileIsExecutable)
	case fields.ImageIsDotnet:
		p, err := pe.ParseFile(kevt.GetParamAsString(kparams.ImagePath), pe.WithCLR())
		if err != nil {
			return nil, err
		}
		return p.IsDotnet, nil
	}

	return nil, nil
}

// registryAccessor extracts registry specific parameters.
type registryAccessor struct{}

func (registryAccessor) SetFields([]Field)            {}
func (registryAccessor) SetSegments([]fields.Segment) {}
func (registryAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.Category == ktypes.Registry
}

func newRegistryAccessor() Accessor {
	return &registryAccessor{}
}

func (r *registryAccessor) Get(f Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f.Name {
	case fields.RegistryPath:
		return kevt.GetParamAsString(kparams.RegPath), nil
	case fields.RegistryKeyName:
		if kevt.IsRegSetValue() {
			return filepath.Base(filepath.Dir(kevt.GetParamAsString(kparams.RegPath))), nil
		} else {
			return filepath.Base(kevt.GetParamAsString(kparams.RegPath)), nil
		}
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

func (n *networkAccessor) SetFields(flds []Field) {
	for _, f := range flds {
		if f.Name == fields.NetSIPNames || f.Name == fields.NetDIPNames {
			n.reverseDNS = network.GetReverseDNS(2000, time.Minute*30, time.Minute*2)
			break
		}
	}
}

func (networkAccessor) SetSegments([]fields.Segment) {}

func (networkAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.Category == ktypes.Net
}

func newNetworkAccessor() Accessor { return &networkAccessor{} }

func (n *networkAccessor) Get(f Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f.Name {
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

func (handleAccessor) SetFields([]Field)            {}
func (handleAccessor) SetSegments([]fields.Segment) {}
func (handleAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.Category == ktypes.Handle
}

func newHandleAccessor() Accessor { return &handleAccessor{} }

func (h *handleAccessor) Get(f Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f.Name {
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
	fields   []Field
	segments []fields.Segment
}

func (pa *peAccessor) SetFields(fields []Field) {
	pa.fields = fields
}
func (pa *peAccessor) SetSegments(segments []fields.Segment) {
	pa.segments = segments
}

func (peAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.PS != nil || kevt.IsLoadImage()
}

// parserOpts traverses all fields/segments declared in the expression and
// dynamically determines what aspects of the PE need to be parsed.
func (pa *peAccessor) parserOpts() []pe.Option {
	var opts []pe.Option
	var peSections bool

	for _, f := range pa.fields {
		if f.Name.IsPeSectionsPseudo() {
			peSections = true
		}
		if f.Name.IsPeSection() || f.Name.IsPeModified() {
			opts = append(opts, pe.WithSections())
		}
		if f.Name.IsPeSymbol() {
			opts = append(opts, pe.WithSymbols())
		}
		if f.Name.IsPeVersionResource() || f.Name.IsPeVersionResources() {
			opts = append(opts, pe.WithVersionResources())
		}
		if f.Name.IsPeImphash() {
			opts = append(opts, pe.WithImphash())
		}
		if f.Name.IsPeDotnet() || f.Name.IsPeModified() {
			opts = append(opts, pe.WithCLR())
		}
		if f.Name.IsPeAnomalies() {
			opts = append(opts, pe.WithSections(), pe.WithSymbols())
		}
		if f.Name.IsPeSignature() {
			opts = append(opts, pe.WithSecurity())
		}
	}

	for _, s := range pa.segments {
		if peSections && s.IsEntropy() {
			opts = append(opts, pe.WithSections(), pe.WithSectionEntropy())
		}
	}

	return opts
}

// ErrPeNilCertificate indicates the PE certificate is not available
var ErrPeNilCertificate = errors.New("pe certificate is nil")

func newPEAccessor() Accessor {
	return &peAccessor{}
}

func (pa *peAccessor) Get(f Field, kevt *kevent.Kevent) (kparams.Value, error) {
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
	if (kevt.PS != nil && kevt.PS.Exe != "" && p == nil) || f.Name == fields.PePsChildFileName || f.Name == fields.PsChildPeFilename {
		var err error
		var exe string
		if (f.Name == fields.PePsChildFileName || f.Name == fields.PsChildPeFilename) && kevt.IsCreateProcess() {
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
	if kevt.IsLoadImage() && f.Name.IsPeModified() {
		filename := kevt.GetParamAsString(kparams.ImagePath)
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
	if f.Name.IsPeSignature() {
		p.VerifySignature()
	}

	if f.Name != fields.PePsChildFileName {
		kevt.PS.PE = p
	}

	switch f.Name {
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
	case fields.PeSections:
		return p.Sections, nil
	case fields.PeResources:
		// return a single version resource indicated by the arg.
		// For example, pe.resources[FileDescription] returns the
		// original file description present in the resource directory
		key := f.Arg
		if key != "" {
			v, ok := p.VersionResources[key]
			if ok {
				return v, nil
			}

			// match on version name prefix
			for k, v := range p.VersionResources {
				if strings.HasPrefix(k, key) {
					return v, nil
				}
			}
		} else {
			// return all version resources as a string slice
			resources := make([]string, 0, len(p.VersionResources))
			for k, v := range p.VersionResources {
				resources = append(resources, k+":"+v)
			}
			return resources, nil
		}
	}

	return nil, nil
}

// memAccessor extracts parameters from memory alloc/free events.
type memAccessor struct{}

func (memAccessor) SetFields([]Field)                          {}
func (memAccessor) SetSegments([]fields.Segment)               {}
func (memAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool { return kevt.Category == ktypes.Mem }

func newMemAccessor() Accessor {
	return &memAccessor{}
}

func (*memAccessor) Get(f Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f.Name {
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

func (dnsAccessor) SetFields([]Field)            {}
func (dnsAccessor) SetSegments([]fields.Segment) {}
func (dnsAccessor) IsFieldAccessible(kevt *kevent.Kevent) bool {
	return kevt.Type.Subcategory() == ktypes.DNS
}

func newDNSAccessor() Accessor {
	return &dnsAccessor{}
}

func (*dnsAccessor) Get(f Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f.Name {
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

// threadpoolAccessor extracts values from thread pool events
type threadpoolAccessor struct{}

func (threadpoolAccessor) SetFields([]Field)            {}
func (threadpoolAccessor) SetSegments([]fields.Segment) {}
func (threadpoolAccessor) IsFieldAccessible(e *kevent.Kevent) bool {
	return e.Category == ktypes.Threadpool
}

func newThreadpoolAccessor() Accessor {
	return &threadpoolAccessor{}
}

func (*threadpoolAccessor) Get(f Field, e *kevent.Kevent) (kparams.Value, error) {
	switch f.Name {
	case fields.ThreadpoolPoolID:
		return e.GetParamAsString(kparams.ThreadpoolPoolID), nil
	case fields.ThreadpoolTaskID:
		return e.GetParamAsString(kparams.ThreadpoolTaskID), nil
	case fields.ThreadpoolCallbackAddress:
		return e.GetParamAsString(kparams.ThreadpoolCallback), nil
	case fields.ThreadpoolCallbackSymbol:
		return e.GetParamAsString(kparams.ThreadpoolCallbackSymbol), nil
	case fields.ThreadpoolCallbackModule:
		return e.GetParamAsString(kparams.ThreadpoolCallbackModule), nil
	case fields.ThreadpoolCallbackContext:
		return e.GetParamAsString(kparams.ThreadpoolContext), nil
	case fields.ThreadpoolCallbackContextRip:
		return e.GetParamAsString(kparams.ThreadpoolContextRip), nil
	case fields.ThreadpoolCallbackContextRipSymbol:
		return e.GetParamAsString(kparams.ThreadpoolContextRipSymbol), nil
	case fields.ThreadpoolCallbackContextRipModule:
		return e.GetParamAsString(kparams.ThreadpoolContextRipModule), nil
	case fields.ThreadpoolSubprocessTag:
		return e.GetParamAsString(kparams.ThreadpoolSubprocessTag), nil
	case fields.ThreadpoolTimer:
		return e.GetParamAsString(kparams.ThreadpoolTimer), nil
	case fields.ThreadpoolTimerSubqueue:
		return e.GetParamAsString(kparams.ThreadpoolTimerSubqueue), nil
	case fields.ThreadpoolTimerDuetime:
		return e.Kparams.GetUint64(kparams.ThreadpoolTimerDuetime)
	case fields.ThreadpoolTimerPeriod:
		return e.Kparams.GetUint32(kparams.ThreadpoolTimerPeriod)
	case fields.ThreadpoolTimerWindow:
		return e.Kparams.GetUint32(kparams.ThreadpoolTimerWindow)
	case fields.ThreadpoolTimerAbsolute:
		return e.Kparams.GetBool(kparams.ThreadpoolTimerAbsolute)
	}

	return nil, nil
}
