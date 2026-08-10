/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package event

import (
	"expvar"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
	"github.com/rabbitstack/fibratus/pkg/util/ip"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/rabbitstack/fibratus/pkg/util/ntstatus"
	"golang.org/x/sys/windows"
)

var unknownKeysCount = expvar.NewInt("registry.unknown.keys.count")

func normalizeParamValue(typ params.Type, value params.Value) params.Value {
	switch typ {
	case params.IPv4:
		return ip.ToIPv4(value.(uint32))
	case params.IPv6:
		return ip.ToIPv6(value.([]byte))
	case params.Port:
		return windows.Ntohs(value.(uint16))
	default:
		return value
	}
}

func formatPlatformParam(p Param) (string, bool) {
	switch p.Type {
	case params.UnicodeString, params.AnsiString, params.Path:
		return p.Value.(string), true
	case params.SID, params.WbemSID:
		sid, err := getSID(&p)
		if err != nil {
			return "", true
		}
		if p.Name == params.ProcessTokenIntegrityLevel {
			return sys.RidToString(sid), true
		}
		return sid.String(), true
	case params.DOSPath:
		return fs.GetDevMapper().Convert(p.Value.(string)), true
	case params.Key:
		rootKey, keyName := key.Format(p.Value.(string))
		if keyName != "" && rootKey != key.Invalid {
			return rootKey.String() + "\\" + keyName, true
		}
		if rootKey != key.Invalid {
			return rootKey.String(), true
		}
		unknownKeysCount.Add(1)
		return keyName, true
	case params.HandleType:
		return htypes.ConvertTypeIDToName(p.Value.(uint16)), true
	case params.Status:
		value, ok := p.Value.(uint32)
		if !ok {
			return "", true
		}
		return ntstatus.FormatMessage(value), true
	default:
		return "", false
	}
}

func formatPlatformID(value params.Value) string {
	return strconv.FormatUint(uint64(value.(uint32)), 10)
}

func captureParamType(typ params.Type) params.Type {
	switch typ {
	case params.HandleType, params.DOSPath, params.Key:
		return params.UnicodeString
	default:
		return typ
	}
}

func platformParamColor(p *Param) (string, bool) {
	switch p.Type {
	case params.UnicodeString, params.AnsiString, params.SID:
		return colorizer.Span(colorizer.White, p.String()), true
	case params.Status:
		if p.String() == ntstatus.Success {
			return colorizer.Span(colorizer.Green, p.String()), true
		}
		return colorizer.Span(colorizer.Red, p.String()), true
	default:
		return "", false
	}
}

// NewParamFromCapture builds a parameter from restored capture state.
func NewParamFromCapture(name string, typ params.Type, value params.Value, etype Type) *Param {
	var enum ParamEnum
	var flags ParamFlags
	switch name {
	case params.FileOperation:
		enum = fs.FileCreateDispositions
	case params.FileCreateOptions:
		flags = FileCreateOptionsFlags
	case params.FileAttributes:
		flags = FileAttributeFlags
	case params.FileShareMask:
		flags = FileShareModeFlags
	case params.FileInfoClass:
		enum = fs.FileInfoClasses
	case params.FileType:
		enum = fs.FileTypes
	case params.NetL4Proto:
		enum = network.ProtoNames
	case params.RegValueType:
		enum = key.RegistryValueTypes
	case params.MemAllocType:
		flags = MemAllocationFlags
	case params.FileViewSectionType:
		enum = ViewSectionTypes
	case params.DNSOpts:
		flags = DNSOptsFlags
	case params.DNSRR:
		enum = DNSRecordTypes
	case params.DNSRcode:
		enum = DNSResponseCodes
	case params.DesiredAccess:
		if etype == OpenProcess {
			flags = PsAccessRightFlags
		} else {
			flags = ThreadAccessRightFlags
		}
	case params.MemProtect:
		if etype == VirtualAlloc || etype == VirtualFree {
			flags = MemProtectionFlags
		} else {
			flags = ViewProtectionFlags
		}
	}
	return &Param{Name: name, Type: typ, Value: value, Enum: enum, Flags: flags}
}

// GetPid returns the process identifier.
func (pars Params) GetPid() (uint32, error) {
	return pars.getID(params.ProcessID, params.PID)
}

// MustGetPid returns the process identifier or panics.
func (pars Params) MustGetPid() uint32 {
	id, err := pars.GetPid()
	if err != nil {
		panic(err)
	}
	return id
}

// GetPpid returns the parent process identifier.
func (pars Params) GetPpid() (uint32, error) {
	return pars.getID(params.ProcessParentID, params.PID)
}

// MustGetPpid returns the parent process identifier or panics.
func (pars Params) MustGetPpid() uint32 {
	id, err := pars.GetPpid()
	if err != nil {
		panic(err)
	}
	return id
}

// GetTid returns the thread identifier.
func (pars Params) GetTid() (uint32, error) {
	return pars.getID(params.ThreadID, params.TID)
}

// MustGetTid returns the thread identifier or panics.
func (pars Params) MustGetTid() uint32 {
	id, err := pars.GetTid()
	if err != nil {
		panic(err)
	}
	return id
}

func (pars Params) getID(name string, typ params.Type) (uint32, error) {
	param, err := pars.findParam(name)
	if err != nil {
		return 0, err
	}
	if param.Type != typ {
		return 0, fmt.Errorf("%q parameter has unexpected identifier type", name)
	}
	value, ok := param.Value.(uint32)
	if !ok {
		return 0, fmt.Errorf("unable to type cast %q parameter to uint32 identifier", name)
	}
	return value, nil
}

// GetSID returns the raw Windows security identifier parameter.
func (pars Params) GetSID() (*windows.SID, error) {
	param, err := pars.findParam(params.UserSID)
	if err != nil {
		return nil, err
	}
	return getSID(param)
}

func getSID(param *Param) (*windows.SID, error) {
	sid, ok := param.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("unable to type cast %q parameter to []byte value", param.Name)
	}
	if sid == nil {
		return nil, fmt.Errorf("sid linked to parameter %s is empty", param.Name)
	}
	pointer := uintptr(unsafe.Pointer(&sid[0]))
	if param.Type == params.WbemSID {
		pointer += uintptr(8 * 2)
	}
	return (*windows.SID)(unsafe.Pointer(pointer)), nil
}

// MustGetSID returns the Windows security identifier or panics.
func (pars Params) MustGetSID() *windows.SID {
	sid, err := pars.GetSID()
	if err != nil {
		panic(err)
	}
	return sid
}

var paramDecoder = &ParamDecoder{}

func (e *Event) decodeParams(r *etw.EventRecord) {
	switch r.Header.ProviderID {
	case RegistryEventGUID:
		paramDecoder.DecodeRegistry(r, e)
	case FileEventGUID:
		paramDecoder.DecodeFile(r, e)
	case StackWalkEventGUID:
		paramDecoder.DecodeStackwalk(r, e)
	case AuditAPIEventGUID:
		switch r.Header.EventDescriptor.ID {
		case OpenProcessID:
			paramDecoder.DecodeOpenProcess(r, e)
		case OpenThreadID:
			paramDecoder.DecodeOpenThread(r, e)
		case SetThreadContextID:
			paramDecoder.DecodeSetThreadContext(r, e)
		case CreateSymbolicLinkObjectID:
			paramDecoder.DecodeCreateSymbolicLinkObject(r, e)
		}
	case MemEventGUID:
		paramDecoder.DecodeMemory(r, e)
	case NetworkTCPEventGUID, NetworkUDPEventGUID:
		paramDecoder.DecodeNetwork(r, e)
	case DNSEventGUID:
		paramDecoder.DecodeDNS(r, e)
	case ProcessEventGUID:
		paramDecoder.DecodeProcess(r, e)
	case ModuleEventGUID:
		paramDecoder.DecodeModule(r, e)
	case ThreadEventGUID:
		paramDecoder.DecodeThread(r, e)
	case ThreadpoolEventGUID:
		paramDecoder.DecodeThreadpool(r, e)
	case HandleEventGUID:
		paramDecoder.DecodeHandle(r, e)
	case RegistryKernelEventGUID:
		paramDecoder.DecodeRegSetValueInternal(r, e)
	case ProcessKernelEventGUID:
		switch r.Header.EventDescriptor.ID {
		case CreateProcessInternalID, ProcessRundownInternalID:
			paramDecoder.DecodeProcessInternal(r, e)
		case LoadModuleInternalID:
			paramDecoder.DecodeModuleInternal(r, e)
		}
	}
}
