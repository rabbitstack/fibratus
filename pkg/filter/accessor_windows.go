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
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	psnap "github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/cmdline"
	"github.com/rabbitstack/fibratus/pkg/util/loldrivers"
	"path/filepath"
	"strconv"
	"strings"

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

// accessor dictates the behaviour of the field accessors. One of the main responsibilities of the accessor is
// to extract the underlying parameter for the field given in the filter expression. It can also produce a value
// from the non-params constructs such as process' state or PE metadata.
type accessor interface {
	// get fetches the parameter value for the specified filter field.
	get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error)
	// setFields sets all fields declared in the expression
	setFields(fields []fields.Field)
}

// getAccessors initializes and returns all available accessors.
func getAccessors() []accessor {
	return []accessor{
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

func (psAccessor) setFields(fields []fields.Field) {}

func newPSAccessor(psnap psnap.Snapshotter) accessor { return &psAccessor{psnap: psnap} }

func (ps *psAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
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
	rootAncestor = "root" // represents the root ancestor
	anyAncestor  = "any"  // represents any ancestor in the hierarchy
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

// threadAccessor fetches thread parameters from thread kernel events.
type threadAccessor struct{}

func (threadAccessor) setFields(fields []fields.Field) {}

func newThreadAccessor() accessor {
	return &threadAccessor{}
}

func (t *threadAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.ThreadBasePrio:
		return kevt.Kparams.GetUint8(kparams.BasePrio)
	case fields.ThreadIOPrio:
		return kevt.Kparams.GetUint8(kparams.IOPrio)
	case fields.ThreadPagePrio:
		return kevt.Kparams.GetUint8(kparams.PagePrio)
	case fields.ThreadKstackBase:
		v, err := kevt.Kparams.GetHex(kparams.KstackBase)
		if err != nil {
			return nil, err
		}
		return v.String(), nil
	case fields.ThreadKstackLimit:
		v, err := kevt.Kparams.GetHex(kparams.KstackLimit)
		if err != nil {
			return nil, err
		}
		return v.String(), nil
	case fields.ThreadUstackBase:
		v, err := kevt.Kparams.GetHex(kparams.UstackBase)
		if err != nil {
			return nil, err
		}
		return v.String(), nil
	case fields.ThreadUstackLimit:
		v, err := kevt.Kparams.GetHex(kparams.UstackLimit)
		if err != nil {
			return nil, err
		}
		return v.String(), nil
	case fields.ThreadEntrypoint:
		v, err := kevt.Kparams.GetHex(kparams.StartAddr)
		if err != nil {
			return nil, err
		}
		return v.String(), nil
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
	}
	return nil, nil
}

// evalLOLDrivers interacts with the loldrivers client to determine
// whether the loaded/dropped driver is malicious or vulnerable.
func evalLOLDrivers(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
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

// fileAccessor extracts file specific values.
type fileAccessor struct{}

func (fileAccessor) setFields(flds []fields.Field) {
	for _, f := range flds {
		if f == fields.FileIsDriverVulnerable || f == fields.FileIsDriverMalicious {
			loldrivers.InitClient()
			break
		}
	}
}

func newFileAccessor() accessor {
	return &fileAccessor{}
}

func (l *fileAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
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
	case fields.FileIsDriverVulnerable, fields.FileIsDriverMalicious:
		if kevt.IsCreateDisposition() && kevt.IsSuccess() {
			return evalLOLDrivers(f, kevt)
		}
		return false, nil
	case fields.FileIsDLL:
		return kevt.Kparams.GetBool(kparams.FileIsDLL)
	case fields.FileIsDriver:
		return kevt.Kparams.GetBool(kparams.FileIsDriver)
	case fields.FileIsExecutable:
		return kevt.Kparams.GetBool(kparams.FileIsExecutable)
	}
	return nil, nil
}

// imageAccessor extracts image (DLL) event values.
type imageAccessor struct{}

func (imageAccessor) setFields(flds []fields.Field) {
	for _, f := range flds {
		if f == fields.ImageIsDriverVulnerable || f == fields.ImageIsDriverMalicious {
			loldrivers.InitClient()
			break
		}
	}
}

func newImageAccessor() accessor {
	return &imageAccessor{}
}

func (i *imageAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
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
			return evalLOLDrivers(f, kevt)
		}
		return false, nil
	case fields.ImageIsDLL:
		return kevt.Kparams.GetBool(kparams.FileIsDLL)
	case fields.ImageIsDriver:
		return kevt.Kparams.GetBool(kparams.FileIsDriver)
	case fields.ImageIsExecutable:
		return kevt.Kparams.GetBool(kparams.FileIsExecutable)
	}
	return nil, nil
}

// registryAccessor extracts registry specific parameters.
type registryAccessor struct{}

func (registryAccessor) setFields(fields []fields.Field) {}

func newRegistryAccessor() accessor {
	return &registryAccessor{}
}

func (r *registryAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
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
		if kevt.Category != ktypes.Registry {
			return nil, nil
		}
		return kevt.GetParamAsString(kparams.NTStatus), nil
	}
	return nil, nil
}

// networkAccessor deals with extracting the network specific kernel event parameters.
type networkAccessor struct{}

func (networkAccessor) setFields(fields []fields.Field) {}

func newNetworkAccessor() accessor { return &networkAccessor{} }

func (n *networkAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
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
	case fields.NetSIPNames:
		return kevt.Kparams.GetStringSlice(kparams.NetSIPNames)
	case fields.NetDIPNames:
		return kevt.Kparams.GetStringSlice(kparams.NetDIPNames)
	}
	return nil, nil
}

// handleAccessor extracts handle event values.
type handleAccessor struct{}

func (handleAccessor) setFields(fields []fields.Field) {}

func newHandleAccessor() accessor { return &handleAccessor{} }

func (h *handleAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.HandleID:
		return kevt.Kparams.GetHexAsUint32(kparams.HandleID)
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

func (pa *peAccessor) setFields(fields []fields.Field) {
	pa.fields = fields
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

func newPEAccessor() accessor {
	return &peAccessor{}
}

func (pa *peAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	var p *pe.PE
	if kevt.PS != nil && kevt.PS.PE != nil {
		p = kevt.PS.PE
	}

	// PE enrichment is likely disabled. Load PE data lazily
	// by only requesting parsing of the PE directories that
	// are relevant to the fields present in the expression.
	if kevt.PS != nil && kevt.PS.Exe != "" && p == nil {
		var err error
		exe := kevt.PS.Exe
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

	kevt.PS.PE = p

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
	case fields.PeFileName:
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

func (memAccessor) setFields(fields []fields.Field) {}

func newMemAccessor() accessor {
	return &memAccessor{}
}

func (*memAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
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

func (dnsAccessor) setFields(fields []fields.Field) {}

func newDNSAccessor() accessor {
	return &dnsAccessor{}
}

func (*dnsAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
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
