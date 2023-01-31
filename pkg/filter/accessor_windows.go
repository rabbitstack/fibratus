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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/util/cmdline"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"

	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

// accessor dictates the behaviour of the field accessors. One of the main responsibilities of the accessor is
// to extract the underlying parameter for the field given in the filter expression. It can also produce a value
// from the non-params constructs such as process' state or PE metadata.
type accessor interface {
	// get fetches the parameter value for the specified filter field.
	get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error)
	// canAccess indicates if the particular accessor is able to extract
	// fields from the given event. The filter context is also provided to
	// this method to determine whether the accessor should be visited depending
	// on some condition derived from the filter expression.
	canAccess(kevt *kevent.Kevent, filter *filter) bool
}

// getAccessors initializes and returns all available accessors.
func getAccessors() []accessor {
	return []accessor{
		newPSAccessor(),
		newPEAccessor(),
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

// psAccessor extracts process's state or kevent specific values.
type psAccessor struct{}

func (psAccessor) canAccess(kevt *kevent.Kevent, filter *filter) bool { return filter.useProcAccessor }

func newPSAccessor() accessor { return &psAccessor{} }

func (ps *psAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.PsPid:
		// the process id that is generating the event
		return kevt.PID, nil
	case fields.PsSiblingPid:
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
	case fields.PsSiblingName:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.ProcessName)
	case fields.PsComm:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return ps.Cmdline, nil
	case fields.PsSiblingComm:
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
	case fields.PsSiblingExe:
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
	case fields.PsSiblingArgs:
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
	case fields.PsSiblingSID:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.UserSID)
	case fields.PsSiblingDomain:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		sid, err := kevt.Kparams.GetString(kparams.UserSID)
		if err != nil {
			return nil, err
		}
		return domainFromSID(sid)
	case fields.PsSiblingUsername:
		if kevt.Category != ktypes.Process {
			return nil, nil
		}
		sid, err := kevt.Kparams.GetString(kparams.UserSID)
		if err != nil {
			return nil, err
		}
		return usernameFromSID(sid)
	case fields.PsDomain:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return domainFromSID(ps.SID)
	case fields.PsUsername:
		ps := kevt.PS
		if ps == nil {
			return nil, ErrPsNil
		}
		return usernameFromSID(ps.SID)
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
		return kevt.Kparams.GetSlice(kparams.DesiredAccessNames)
	case fields.PsAccessStatus:
		if kevt.Type != ktypes.OpenProcess {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.NTStatus)
	case fields.PsSiblingSessionID:
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
	case fields.PsParentComm:
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
		return domainFromSID(ps.SID)
	case fields.PsParentUsername:
		ps := getParentPs(kevt)
		if ps == nil {
			return nil, ErrPsNil
		}
		return usernameFromSID(ps.SID)
	case fields.PsParentSessionID:
		parent := getParentPs(kevt)
		if parent == nil {
			return nil, ErrPsNil
		}
		return parent.SessionID, nil
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
		case f.IsEnvsSequence():
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
		case f.IsModsSequence():
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
		case f.IsAncestorSequence():
			return ancestorFields(f.String(), kevt)
		}

		return nil, nil
	}
}

func domainFromSID(sid string) (string, error) {
	s := strings.Split(sid, "\\")
	if len(s) != 2 {
		return "", fmt.Errorf("illegal split for the domain field. Expected 2 but got %d substrings", len(s))
	}
	return s[0], nil
}

func usernameFromSID(sid string) (string, error) {
	s := strings.Split(sid, "\\")
	if len(s) != 2 {
		return "", fmt.Errorf("illegal split for the username field. Expected 2 but got %d substrings", len(s))
	}
	return s[1], nil
}

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
	case "root":
		walk := func(proc *pstypes.PS) {
			ps = proc
		}
		pstypes.Walk(walk, kevt.PS)
	case "any":
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
			case fields.ProcessComm:
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
	case fields.ProcessComm:
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

func (threadAccessor) canAccess(kevt *kevent.Kevent, filter *filter) bool {
	return kevt.Category == ktypes.Thread
}

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
		return kevt.Kparams.GetSlice(kparams.DesiredAccessNames)
	case fields.ThreadAccessStatus:
		if kevt.Type != ktypes.OpenThread {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.NTStatus)
	}
	return nil, nil
}

// fileAccessor extracts file specific values.
type fileAccessor struct{}

func (fileAccessor) canAccess(kevt *kevent.Kevent, filter *filter) bool {
	return kevt.Category == ktypes.File
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
		m, err := kevt.Kparams.GetRaw(kparams.FileShareMask)
		if err != nil {
			return nil, err
		}
		mode, ok := m.(fs.FileShareMode)
		if !ok {
			return nil, errors.New("couldn't type assert to file share mode enum")
		}
		return mode.String(), nil
	case fields.FileOperation:
		return kevt.GetParamAsString(kparams.FileOperation), nil
	case fields.FileObject:
		return kevt.Kparams.GetUint64(kparams.FileObject)
	case fields.FileType:
		return kevt.GetParamAsString(kparams.FileType), nil
	case fields.FileExtension:
		return filepath.Ext(kevt.GetParamAsString(kparams.FileName)), nil
	case fields.FileAttributes:
		val, err := kevt.Kparams.GetSlice(kparams.FileAttributes)
		if err != nil {
			return nil, err
		}
		slice, ok := val.([]fs.FileAttr)
		if !ok {
			return nil, nil
		}
		// convert from []fs.FileAttr to string slice
		attrs := make([]string, 0, len(slice))
		for _, attr := range slice {
			attrs = append(attrs, attr.String())
		}
		return attrs, nil
	case fields.FileStatus:
		if kevt.Type != ktypes.CreateFile {
			return nil, nil
		}
		return kevt.Kparams.GetString(kparams.NTStatus)
	}
	return nil, nil
}

// imageAccessor extracts image (DLL) event values.
type imageAccessor struct{}

func (imageAccessor) canAccess(kevt *kevent.Kevent, filter *filter) bool {
	return kevt.Category == ktypes.Image
}

func newImageAccessor() accessor {
	return &imageAccessor{}
}

func (i *imageAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.ImageName:
		return kevt.Kparams.GetString(kparams.ImageFilename)
	case fields.ImageDefaultAddress:
		address, err := kevt.Kparams.GetHex(kparams.ImageDefaultBase)
		if err != nil {
			return nil, err
		}
		return address.String(), nil
	case fields.ImageBase:
		address, err := kevt.Kparams.GetHex(kparams.ImageBase)
		if err != nil {
			return nil, err
		}
		return address.String(), nil
	case fields.ImageSize:
		return kevt.Kparams.GetUint32(kparams.ImageSize)
	case fields.ImageChecksum:
		return kevt.Kparams.GetUint32(kparams.ImageCheckSum)
	case fields.ImagePID:
		return kevt.Kparams.GetPid()
	}
	return nil, nil
}

// registryAccessor extracts registry specific parameters.
type registryAccessor struct{}

func (registryAccessor) canAccess(kevt *kevent.Kevent, filter *filter) bool {
	return kevt.Category == ktypes.Registry
}

func newRegistryAccessor() accessor {
	return &registryAccessor{}
}

func (r *registryAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.RegistryKeyName:
		return kevt.Kparams.GetString(kparams.RegKeyName)
	case fields.RegistryKeyHandle:
		keyHandle, err := kevt.Kparams.GetHex(kparams.RegKeyHandle)
		if err != nil {
			return nil, err
		}
		return keyHandle.String(), nil
	case fields.RegistryValue:
		return kevt.Kparams.Get(kparams.RegValue)
	case fields.RegistryValueType:
		return kevt.Kparams.GetString(kparams.RegValueType)
	case fields.RegistryStatus:
		return kevt.Kparams.GetString(kparams.NTStatus)
	}
	return nil, nil
}

// networkAccessor deals with extracting the network specific kernel event parameters.
type networkAccessor struct{}

func (networkAccessor) canAccess(kevt *kevent.Kevent, filter *filter) bool {
	return kevt.Category == ktypes.Net
}

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
		v, err := kevt.Kparams.GetRaw(kparams.NetL4Proto)
		if err != nil {
			return nil, err
		}
		l4proto, ok := v.(network.L4Proto)
		if !ok {
			return nil, errors.New("couldn't type assert to L4 proto enum")
		}
		return l4proto.String(), nil
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

func (handleAccessor) canAccess(kevt *kevent.Kevent, filter *filter) bool {
	return kevt.Category == ktypes.Handle
}

func newHandleAccessor() accessor { return &handleAccessor{} }

func (h *handleAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	switch f {
	case fields.HandleID:
		return kevt.Kparams.GetHexAsUint32(kparams.HandleID)
	case fields.HandleType:
		return kevt.Kparams.GetString(kparams.HandleObjectTypeName)
	case fields.HandleName:
		return kevt.Kparams.GetString(kparams.HandleObjectName)
	case fields.HandleObject:
		handleObject, err := kevt.Kparams.GetHex(kparams.HandleObject)
		if err != nil {
			return nil, err
		}
		return handleObject.String(), nil
	}
	return nil, nil
}

// peAccessor extracts PE specific values.
type peAccessor struct{}

func (peAccessor) canAccess(kevt *kevent.Kevent, filter *filter) bool { return true }

func newPEAccessor() accessor {
	return &peAccessor{}
}

func (*peAccessor) get(f fields.Field, kevt *kevent.Kevent) (kparams.Value, error) {
	var p *pe.PE
	if kevt.PS != nil && kevt.PS.PE != nil {
		p = kevt.PS.PE
	}
	if p == nil {
		return nil, nil
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
		case f.IsPeSectionsSequence():
			// get the section name
			sname, segment := captureInBrackets(f.String())
			sec := p.Section(sname)
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
		case f.IsPeResourcesSequence():
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
