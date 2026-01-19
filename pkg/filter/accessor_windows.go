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
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/network"
	psnap "github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/signature"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
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
		newEventAccessor(),
		newImageAccessor(),
		newThreadAccessor(),
		newHandleAccessor(),
		newNetworkAccessor(),
		newRegistryAccessor(),
		newThreadpoolAccessor(),
	}
}

func getParentPs(e *event.Event) *pstypes.PS {
	if e.PS == nil {
		return nil
	}
	return e.PS.Parent
}

// psAccessor extracts process's state or event specific values.
type psAccessor struct {
	psnap psnap.Snapshotter
}

func (psAccessor) SetFields([]Field)            {}
func (psAccessor) SetSegments([]fields.Segment) {}
func (psAccessor) IsFieldAccessible(e *event.Event) bool {
	return e.PS != nil || e.Category == event.Process
}

func newPSAccessor(psnap psnap.Snapshotter) Accessor { return &psAccessor{psnap: psnap} }

func (ps *psAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.PsPid:
		return e.PID, nil
	case fields.PsPpid:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Ppid, nil
	case fields.PsName:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Name, nil
	case fields.PsComm, fields.PsCmdline:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Cmdline, nil
	case fields.PsExe:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Exe, nil
	case fields.PsArgs:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Args, nil
	case fields.PsCwd:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Cwd, nil
	case fields.PsSID:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.SID, nil
	case fields.PsIsWOW64Field:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsWOW64, nil
	case fields.PsIsPackagedField:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsPackaged, nil
	case fields.PsIsProtectedField:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsProtected, nil
	case fields.PsDomain:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Domain, nil
	case fields.PsUsername:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Username, nil
	case fields.PsSessionID:
		ps := e.PS
		if ps == nil {
			return nil, nil
		}
		return ps.SessionID, nil
	case fields.PsAccessMask:
		if e.Type != event.OpenProcess {
			return nil, nil
		}
		return e.Params.GetString(params.DesiredAccess)
	case fields.PsAccessMaskNames:
		if e.Type != event.OpenProcess {
			return nil, nil
		}
		return e.GetFlagsAsSlice(params.DesiredAccess), nil
	case fields.PsAccessStatus:
		if e.Type != event.OpenProcess {
			return nil, nil
		}
		return e.GetParamAsString(params.NTStatus), nil
	case fields.PsModuleNames:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		mods := make([]string, 0, len(ps.Modules))
		for _, m := range ps.Modules {
			mods = append(mods, filepath.Base(m.Name))
		}
		return mods, nil
	case fields.PsUUID:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.UUID(), nil
	case fields.PsParentUUID:
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.UUID(), nil
	case fields.PsHandleNames:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		handles := make([]string, len(ps.Handles))
		for i, handle := range ps.Handles {
			handles[i] = handle.Name
		}
		return handles, nil
	case fields.PsHandleTypes:
		ps := e.PS
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
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.PID, nil
	case fields.PsParentName:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Name, nil
	case fields.PsParentComm, fields.PsParentCmdline:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Cmdline, nil
	case fields.PsParentExe:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Exe, nil
	case fields.PsParentArgs:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Args, nil
	case fields.PsParentCwd:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.Cwd, nil
	case fields.PsParentSID:
		parent := getParentPs(e)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.SID, nil
	case fields.PsParentDomain:
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Domain, nil
	case fields.PsParentUsername:
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Username, nil
	case fields.PsParentSessionID:
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.SessionID, nil
	case fields.PsParentEnvs:
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		envs := make([]string, 0, len(ps.Envs))
		for k, v := range ps.Envs {
			envs = append(envs, k+":"+v)
		}
		return envs, nil
	case fields.PsParentHandles:
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		handles := make([]string, len(ps.Handles))
		for i, handle := range ps.Handles {
			handles[i] = handle.Name
		}
		return handles, nil
	case fields.PsParentHandleTypes:
		ps := getParentPs(e)
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
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsWOW64, nil
	case fields.PsParentIsPackagedField:
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsPackaged, nil
	case fields.PsParentIsProtectedField:
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsProtected, nil
	case fields.PsTokenIntegrityLevel:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.TokenIntegrityLevel, nil
	case fields.PsTokenElevationType:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.TokenElevationType, nil
	case fields.PsTokenIsElevated:
		ps := e.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsTokenElevated, nil
	case fields.PsParentTokenIntegrityLevel:
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.TokenIntegrityLevel, nil
	case fields.PsParentTokenElevationType:
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.TokenElevationType, nil
	case fields.PsParentTokenIsElevated:
		ps := getParentPs(e)
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.IsTokenElevated, nil
	case fields.PsAncestors:
		if e.PS != nil {
			ancestors := make([]*pstypes.PS, 0)
			walk := func(proc *pstypes.PS) {
				if proc != nil {
					ancestors = append(ancestors, proc)
				}
			}
			pstypes.Walk(walk, e.PS)

			return ancestors, nil
		}
		return nil, ErrPsNil
	case fields.PsModules:
		if e.PS != nil {
			return e.PS.Modules, nil
		}
		return nil, ErrPsNil
	case fields.PsThreads:
		if e.PS != nil {
			return e.PS.Threads, nil
		}
		return nil, ErrPsNil
	case fields.PsMmaps:
		if e.PS != nil {
			return e.PS.Mmaps, nil
		}
		return nil, ErrPsNil
	case fields.PsAncestor:
		if e.PS != nil {
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
				if proc != nil {
					ancestors = append(ancestors, proc.Name)
				}
			}
			pstypes.Walk(walk, e.PS)

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
		ps := e.PS
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
func (threadAccessor) IsFieldAccessible(e *event.Event) bool {
	return !e.Callstack.IsEmpty() || e.Category == event.Thread
}

func newThreadAccessor() Accessor {
	return &threadAccessor{}
}

func (t *threadAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.ThreadBasePrio:
		return e.Params.GetUint8(params.BasePrio)
	case fields.ThreadIOPrio:
		return e.Params.GetUint8(params.IOPrio)
	case fields.ThreadPagePrio:
		return e.Params.GetUint8(params.PagePrio)
	case fields.ThreadKstackBase:
		return e.GetParamAsString(params.KstackBase), nil
	case fields.ThreadKstackLimit:
		return e.GetParamAsString(params.KstackLimit), nil
	case fields.ThreadUstackBase:
		return e.GetParamAsString(params.UstackBase), nil
	case fields.ThreadUstackLimit:
		return e.GetParamAsString(params.UstackLimit), nil
	case fields.ThreadEntrypoint, fields.ThreadStartAddress:
		return e.GetParamAsString(params.StartAddress), nil
	case fields.ThreadPID:
		return e.Params.GetUint32(params.ProcessID)
	case fields.ThreadTEB:
		return e.GetParamAsString(params.TEB), nil
	case fields.ThreadAccessMask:
		if e.Type != event.OpenThread {
			return nil, nil
		}
		return e.Params.GetString(params.DesiredAccess)
	case fields.ThreadAccessMaskNames:
		if e.Type != event.OpenThread {
			return nil, nil
		}
		return e.GetFlagsAsSlice(params.DesiredAccess), nil
	case fields.ThreadAccessStatus:
		if e.Type != event.OpenThread {
			return nil, nil
		}
		return e.GetParamAsString(params.NTStatus), nil
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
		return e.Callstack.AllocationSizes(framePID(e)), nil
	case fields.ThreadCallstackProtections:
		return e.Callstack.Protections(framePID(e)), nil
	case fields.ThreadCallstackCallsiteLeadingAssembly:
		return e.Callstack.CallsiteInsns(framePID(e), true), nil
	case fields.ThreadCallstackCallsiteTrailingAssembly:
		return e.Callstack.CallsiteInsns(framePID(e), false), nil
	case fields.ThreadCallstackIsUnbacked:
		return e.Callstack.ContainsUnbacked(), nil
	case fields.ThreadCallstack:
		return e.Callstack, nil
	case fields.ThreadStartAddressSymbol:
		if e.Type != event.CreateThread {
			return nil, nil
		}
		return e.GetParamAsString(params.StartAddressSymbol), nil
	case fields.ThreadStartAddressModule:
		if e.Type != event.CreateThread {
			return nil, nil
		}
		return e.GetParamAsString(params.StartAddressModule), nil
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

func (fileAccessor) IsFieldAccessible(e *event.Event) bool { return e.Category == event.File }

func newFileAccessor() Accessor {
	return &fileAccessor{}
}

func (l *fileAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.FilePath:
		return e.GetParamAsString(params.FilePath), nil
	case fields.FilePathStem:
		path := e.GetParamAsString(params.FilePath)
		n := strings.LastIndexByte(path, '.')
		if n == -1 {
			return path, nil
		}
		return path[:n], nil
	case fields.FileName:
		return filepath.Base(e.GetParamAsString(params.FilePath)), nil
	case fields.FileExtension:
		return filepath.Ext(e.GetParamAsString(params.FilePath)), nil
	case fields.FileOffset:
		return e.Params.GetUint64(params.FileOffset)
	case fields.FileIOSize:
		return e.Params.GetUint32(params.FileIoSize)
	case fields.FileShareMask:
		return e.GetParamAsString(params.FileShareMask), nil
	case fields.FileOperation:
		return e.GetParamAsString(params.FileOperation), nil
	case fields.FileObject:
		return e.Params.GetUint64(params.FileObject)
	case fields.FileType:
		return e.GetParamAsString(params.FileType), nil
	case fields.FileAttributes:
		return e.GetFlagsAsSlice(params.FileAttributes), nil
	case fields.FileStatus:
		if e.Type != event.CreateFile {
			return nil, nil
		}
		return e.GetParamAsString(params.NTStatus), nil
	case fields.FileViewBase:
		return e.GetParamAsString(params.FileViewBase), nil
	case fields.FileViewSize:
		return e.Params.GetUint64(params.FileViewSize)
	case fields.FileViewType:
		return e.GetParamAsString(params.FileViewSectionType), nil
	case fields.FileViewProtection:
		return e.GetParamAsString(params.MemProtect), nil
	case fields.FileIsDriverVulnerable, fields.FileIsDriverMalicious:
		if e.IsCreateDisposition() && e.IsSuccess() {
			return isLOLDriver(f.Name, e)
		}
		return false, nil
	case fields.FileIsDLL:
		return e.Params.GetBool(params.FileIsDLL)
	case fields.FileIsDriver:
		return e.Params.GetBool(params.FileIsDriver)
	case fields.FileIsExecutable:
		return e.Params.GetBool(params.FileIsExecutable)
	case fields.FilePID:
		return e.Params.GetPid()
	case fields.FileKey:
		return e.Params.GetUint64(params.FileKey)
	case fields.FileInfoClass:
		return e.GetParamAsString(params.FileInfoClass), nil
	case fields.FileInfoAllocationSize:
		if e.Params.TryGetUint32(params.FileInfoClass) == fs.AllocationClass {
			return e.Params.GetUint64(params.FileExtraInfo)
		}
	case fields.FileInfoEOFSize:
		if e.Params.TryGetUint32(params.FileInfoClass) == fs.EOFClass {
			return e.Params.GetUint64(params.FileExtraInfo)
		}
	case fields.FileInfoIsDispositionDeleteFile:
		return e.Params.TryGetUint32(params.FileInfoClass) == fs.DispositionClass &&
			e.Params.TryGetUint64(params.FileExtraInfo) > 0, nil
	}

	return nil, nil
}

// imageAccessor extracts image (DLL, executable, driver) event values.
type imageAccessor struct{}

func (imageAccessor) SetFields(fields []Field) {
	initLOLDriversClient(fields)
}
func (imageAccessor) SetSegments([]fields.Segment) {}

func (imageAccessor) IsFieldAccessible(e *event.Event) bool {
	return e.Category == event.Image
}

func newImageAccessor() Accessor {
	return &imageAccessor{}
}

func (i *imageAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	if e.IsLoadImage() && (f.Name == fields.ImageSignatureType || f.Name == fields.ImageSignatureLevel || f.Name.IsImageCert()) {
		filename := e.GetParamAsString(params.ImagePath)
		addr := e.Params.MustGetUint64(params.ImageBase)
		typ := e.Params.MustGetUint32(params.ImageSignatureType)
		level := e.Params.MustGetUint32(params.ImageSignatureLevel)

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
			_ = e.Params.SetValue(params.ImageSignatureType, sign.Type)
			_ = e.Params.SetValue(params.ImageSignatureLevel, sign.Level)
		}

		// append certificate parameters
		if sign.HasCertificate() {
			e.AppendParam(params.ImageCertIssuer, params.UnicodeString, sign.Cert.Issuer)
			e.AppendParam(params.ImageCertSubject, params.UnicodeString, sign.Cert.Subject)
			e.AppendParam(params.ImageCertSerial, params.UnicodeString, sign.Cert.SerialNumber)
			e.AppendParam(params.ImageCertNotAfter, params.Time, sign.Cert.NotAfter)
			e.AppendParam(params.ImageCertNotBefore, params.Time, sign.Cert.NotBefore)
		}
	}

	switch f.Name {
	case fields.ImagePath:
		return e.GetParamAsString(params.ImagePath), nil
	case fields.ImagePathStem:
		path := e.GetParamAsString(params.ImagePath)
		n := strings.LastIndexByte(path, '.')
		if n == -1 {
			return path, nil
		}
		return path[:n], nil
	case fields.ImageName:
		return filepath.Base(e.GetParamAsString(params.ImagePath)), nil
	case fields.ImageDefaultAddress:
		return e.GetParamAsString(params.ImageDefaultBase), nil
	case fields.ImageBase:
		return e.GetParamAsString(params.ImageBase), nil
	case fields.ImageSize:
		return e.Params.GetUint64(params.ImageSize)
	case fields.ImageChecksum:
		return e.Params.GetUint32(params.ImageCheckSum)
	case fields.ImagePID:
		return e.Params.GetPid()
	case fields.ImageSignatureType:
		return e.GetParamAsString(params.ImageSignatureType), nil
	case fields.ImageSignatureLevel:
		return e.GetParamAsString(params.ImageSignatureLevel), nil
	case fields.ImageCertSubject:
		return e.GetParamAsString(params.ImageCertSubject), nil
	case fields.ImageCertIssuer:
		return e.GetParamAsString(params.ImageCertIssuer), nil
	case fields.ImageCertSerial:
		return e.GetParamAsString(params.ImageCertSerial), nil
	case fields.ImageCertBefore:
		return e.Params.GetTime(params.ImageCertNotBefore)
	case fields.ImageCertAfter:
		return e.Params.GetTime(params.ImageCertNotAfter)
	case fields.ImageIsDriverVulnerable, fields.ImageIsDriverMalicious:
		if e.IsLoadImage() {
			return isLOLDriver(f.Name, e)
		}
		return false, nil
	case fields.ImageIsDLL:
		return e.Params.GetBool(params.FileIsDLL)
	case fields.ImageIsDriver:
		return e.Params.GetBool(params.FileIsDriver)
	case fields.ImageIsExecutable:
		return e.Params.GetBool(params.FileIsExecutable)
	case fields.ImageIsDotnet:
		return e.Params.GetBool(params.FileIsDotnet)
	}

	return nil, nil
}

// registryAccessor extracts registry specific parameters.
type registryAccessor struct{}

func (registryAccessor) SetFields([]Field)            {}
func (registryAccessor) SetSegments([]fields.Segment) {}
func (registryAccessor) IsFieldAccessible(e *event.Event) bool {
	return e.Category == event.Registry
}

func newRegistryAccessor() Accessor {
	return &registryAccessor{}
}

func (r *registryAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.RegistryPath:
		return e.GetParamAsString(params.RegPath), nil
	case fields.RegistryKeyName:
		if e.IsRegSetValue() {
			return filepath.Base(filepath.Dir(e.GetParamAsString(params.RegPath))), nil
		} else {
			return filepath.Base(e.GetParamAsString(params.RegPath)), nil
		}
	case fields.RegistryKeyHandle:
		return e.GetParamAsString(params.RegKeyHandle), nil
	case fields.RegistryValue:
		if e.IsRegSetValue() {
			return filepath.Base(filepath.Base(e.GetParamAsString(params.RegPath))), nil
		}
		return nil, nil
	case fields.RegistryValueType:
		return e.Params.GetString(params.RegValueType)
	case fields.RegistryData:
		return e.GetParamAsString(params.RegData), nil
	case fields.RegistryStatus:
		return e.GetParamAsString(params.NTStatus), nil
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

func (networkAccessor) IsFieldAccessible(e *event.Event) bool {
	return e.Category == event.Net
}

func newNetworkAccessor() Accessor { return &networkAccessor{} }

func (n *networkAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.NetDIP:
		return e.Params.GetIP(params.NetDIP)
	case fields.NetSIP:
		return e.Params.GetIP(params.NetSIP)
	case fields.NetDport:
		return e.Params.GetUint16(params.NetDport)
	case fields.NetSport:
		return e.Params.GetUint16(params.NetSport)
	case fields.NetDportName:
		return e.Params.GetString(params.NetDportName)
	case fields.NetSportName:
		return e.Params.GetString(params.NetSportName)
	case fields.NetL4Proto:
		return e.GetParamAsString(params.NetL4Proto), nil
	case fields.NetPacketSize:
		return e.Params.GetUint32(params.NetSize)
	case fields.NetDIPNames:
		return n.resolveNamesForIP(e.Params.MustGetIP(params.NetDIP))
	case fields.NetSIPNames:
		return n.resolveNamesForIP(e.Params.MustGetIP(params.NetSIP))
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
func (handleAccessor) IsFieldAccessible(e *event.Event) bool {
	return e.Category == event.Handle
}

func newHandleAccessor() Accessor { return &handleAccessor{} }

func (h *handleAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.HandleID:
		return e.Params.GetUint32(params.HandleID)
	case fields.HandleType:
		return e.GetParamAsString(params.HandleObjectTypeID), nil
	case fields.HandleName:
		return e.Params.GetString(params.HandleObjectName)
	case fields.HandleObject:
		return e.Params.GetUint64(params.HandleObject)
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

func (peAccessor) IsFieldAccessible(e *event.Event) bool {
	return e.PS != nil || e.IsLoadImage()
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

func (pa *peAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	var p *pe.PE
	if e.PS != nil && e.PS.PE != nil {
		p = e.PS.PE
	}

	// PE enrichment is likely disabled. Load PE data lazily
	// by only requesting parsing of the PE directories that
	// are relevant to the fields present in the expression.
	if e.PS != nil && e.PS.Exe != "" && p == nil {
		var err error
		exe := e.PS.Exe
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
	if e.IsLoadImage() && f.Name.IsPeModified() {
		filename := e.GetParamAsString(params.ImagePath)
		isExecutable := filepath.Ext(filename) == ".exe" || e.Params.TryGetBool(params.FileIsExecutable)
		if !isExecutable {
			return nil, nil
		}

		pid := e.Params.MustGetPid()
		addr := e.Params.MustGetUint64(params.ImageBase)

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

	e.PS.PE = p

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
		return e.Params.GetBool(params.FileIsDLL)
	case fields.PeIsDriver:
		return e.Params.GetBool(params.FileIsDriver)
	case fields.PeIsExecutable:
		return e.Params.GetBool(params.FileIsExecutable)
	case fields.PeCompany:
		return p.VersionResources[pe.Company], nil
	case fields.PeCopyright:
		return p.VersionResources[pe.LegalCopyright], nil
	case fields.PeDescription:
		return p.VersionResources[pe.FileDescription], nil
	case fields.PeFileName:
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

func (memAccessor) SetFields([]Field)                     {}
func (memAccessor) SetSegments([]fields.Segment)          {}
func (memAccessor) IsFieldAccessible(e *event.Event) bool { return e.Category == event.Mem }

func newMemAccessor() Accessor {
	return &memAccessor{}
}

func (*memAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.MemPageType:
		return e.GetParamAsString(params.MemPageType), nil
	case fields.MemAllocType:
		return e.GetParamAsString(params.MemAllocType), nil
	case fields.MemProtection:
		return e.GetParamAsString(params.MemProtect), nil
	case fields.MemBaseAddress:
		return e.Params.GetUint64(params.MemBaseAddress)
	case fields.MemRegionSize:
		return e.Params.GetUint64(params.MemRegionSize)
	case fields.MemProtectionMask:
		return e.Params.GetString(params.MemProtectMask)
	}

	return nil, nil
}

// dnsAccessor extracts values from DNS query/response event parameters.
type dnsAccessor struct{}

func (dnsAccessor) SetFields([]Field)            {}
func (dnsAccessor) SetSegments([]fields.Segment) {}
func (dnsAccessor) IsFieldAccessible(e *event.Event) bool {
	return e.Type.Subcategory() == event.DNS
}

func newDNSAccessor() Accessor {
	return &dnsAccessor{}
}

func (*dnsAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.DNSName:
		return e.GetParamAsString(params.DNSName), nil
	case fields.DNSRR:
		return e.GetParamAsString(params.DNSRR), nil
	case fields.DNSRcode:
		return e.GetParamAsString(params.DNSRcode), nil
	case fields.DNSOptions:
		return e.GetFlagsAsSlice(params.DNSOpts), nil
	case fields.DNSAnswers:
		return e.Params.GetSlice(params.DNSAnswers)
	}

	return nil, nil
}

// threadpoolAccessor extracts values from thread pool events
type threadpoolAccessor struct{}

func (threadpoolAccessor) SetFields([]Field)            {}
func (threadpoolAccessor) SetSegments([]fields.Segment) {}
func (threadpoolAccessor) IsFieldAccessible(e *event.Event) bool {
	return e.Category == event.Threadpool
}

func newThreadpoolAccessor() Accessor {
	return &threadpoolAccessor{}
}

func (*threadpoolAccessor) Get(f Field, e *event.Event) (params.Value, error) {
	switch f.Name {
	case fields.ThreadpoolPoolID:
		return e.GetParamAsString(params.ThreadpoolPoolID), nil
	case fields.ThreadpoolTaskID:
		return e.GetParamAsString(params.ThreadpoolTaskID), nil
	case fields.ThreadpoolCallbackAddress:
		return e.GetParamAsString(params.ThreadpoolCallback), nil
	case fields.ThreadpoolCallbackSymbol:
		return e.GetParamAsString(params.ThreadpoolCallbackSymbol), nil
	case fields.ThreadpoolCallbackModule:
		return e.GetParamAsString(params.ThreadpoolCallbackModule), nil
	case fields.ThreadpoolCallbackContext:
		return e.GetParamAsString(params.ThreadpoolContext), nil
	case fields.ThreadpoolCallbackContextRip:
		return e.GetParamAsString(params.ThreadpoolContextRip), nil
	case fields.ThreadpoolCallbackContextRipSymbol:
		return e.GetParamAsString(params.ThreadpoolContextRipSymbol), nil
	case fields.ThreadpoolCallbackContextRipModule:
		return e.GetParamAsString(params.ThreadpoolContextRipModule), nil
	case fields.ThreadpoolSubprocessTag:
		return e.GetParamAsString(params.ThreadpoolSubprocessTag), nil
	case fields.ThreadpoolTimer:
		return e.GetParamAsString(params.ThreadpoolTimer), nil
	case fields.ThreadpoolTimerSubqueue:
		return e.GetParamAsString(params.ThreadpoolTimerSubqueue), nil
	case fields.ThreadpoolTimerDuetime:
		return e.Params.GetUint64(params.ThreadpoolTimerDuetime)
	case fields.ThreadpoolTimerPeriod:
		return e.Params.GetUint32(params.ThreadpoolTimerPeriod)
	case fields.ThreadpoolTimerWindow:
		return e.Params.GetUint32(params.ThreadpoolTimerWindow)
	case fields.ThreadpoolTimerAbsolute:
		return e.Params.GetBool(params.ThreadpoolTimerAbsolute)
	}

	return nil, nil
}
