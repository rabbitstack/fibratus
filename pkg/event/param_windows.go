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
	"strconv"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/rabbitstack/fibratus/pkg/util/ntstatus"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
)

var unknownKeysCount = expvar.NewInt("registry.unknown.keys.count")

// String returns the string representation of the parameter. The parameter
// value is resolved according to the parameter type.
func (p Param) String() string {
	v := p.Value
	if v.IsNull() {
		return ""
	}
	switch p.Type() {
	case params.String, params.Path:
		return v.Str()
	case params.SID, params.WbemSID, params.TokenIntegrityLevel:
		sid := convertToSID(p)
		if sid == nil {
			return ""
		}
		if p.Type() == params.TokenIntegrityLevel {
			return sys.RidToString(sid)
		}
		return sid.String()
	case params.DOSPath:
		return fs.GetDevMapper().Convert(v.Str())
	case params.Key:
		rootKey, keyName := key.Format(v.Str())
		if keyName != "" && rootKey != key.Invalid {
			return rootKey.String() + "\\" + keyName
		}
		if rootKey != key.Invalid {
			return rootKey.String()
		}
		unknownKeysCount.Add(1)
		return keyName
	case params.HandleType:
		return htypes.ConvertTypeIDToName(v.Uint16())
	case params.Status:
		if v.Kind() != params.KindUint {
			return ""
		}
		return ntstatus.FormatMessage(v.Uint32())
	case params.Address:
		if v.Kind() != params.KindUint {
			return ""
		}
		return va.Address(v.Uint64()).String()
	case params.Int8, params.Int16, params.Int32, params.Int64:
		return strconv.FormatInt(v.Int64(), 10)
	case params.Uint8, params.Uint16, params.Uint32, params.Uint64, params.Port, params.PID, params.TID:
		return strconv.FormatUint(v.Uint64(), 10)
	case params.IP, params.IPv4, params.IPv6:
		return v.IP().String()
	case params.Enum:
		enum := p.Enum()
		if enum == nil || v.Kind() != params.KindUint {
			return ""
		}
		return enum[v.Uint32()]
	case params.Flags32, params.Flags64:
		flags := p.Flags()
		if flags == nil || v.Kind() != params.KindUint {
			return ""
		}
		return flags.String(v.Uint64())
	default:
		// bool, float, time, slice, binary, and variant
		// types are rendered according to the value kind
		return v.String()
	}
}

// CaptureType returns the event type saved inside the capture file.
// Captures usually override the type of the parameter to provide
// consistent replay experience. For example, the file path param
// type is converted to string param type, as drive mapping is performed
// on the target where the capture is being taken.
func (p Param) CaptureType() params.Type {
	switch p.Type() {
	case params.HandleType, params.DOSPath, params.Key, params.String:
		return params.String
	case params.IP, params.IPv4, params.IPv6:
		if p.Value.IsIPv4() {
			return params.IPv4
		}
		return params.IPv6
	case params.Variant:
		t := p.Value.ParamType()
		if t == params.IP {
			if p.Value.IsIPv4() {
				return params.IPv4
			}
			return params.IPv6
		}
		return params.String
	default:
		return p.Type()
	}
}

// setFromCapture sets the parameter restored from the capture state. If the schema
// declares the parameter, the value is assigned to the existing slot. Parameter types that
// the capture converts to strings are given the string type, so the value is not converted
// again when the parameter is rendered.
func (pars *Params) setFromCapture(name string, typ params.Type, v params.Value) {
	i := pars.Index(name)
	if i < 0 {
		*pars = append(*pars, Param{Value: v, info: &params.ParamInfo{Name: name, Type: typ}})
		return
	}
	cur := (*pars)[i].info
	switch cur.Type {
	case params.HandleType, params.DOSPath, params.Key:
		info := *cur
		info.Type = params.String
		(*pars)[i].info = &info
	}
	(*pars)[i].Value = v
}

// GetPid returns the process identifier.
func (pars Params) GetPid() uint32 { return pars.GetUint32ByName(params.ProcessID) }

// GetPpid returns the parent process identifier.
func (pars Params) GetPpid() uint32 { return pars.GetUint32ByName(params.ProcessParentID) }

// GetTid returns the thread identifier.
func (pars Params) GetTid() uint32 { return pars.GetUint32ByName(params.ThreadID) }

// GetSID returns the raw Windows security identifier parameter.
// It returns nil if the parameter is absent or has an invalid value.
func (pars Params) GetSID() *windows.SID { return convertToSID(pars.GetByName(params.UserSID)) }

func convertToSID(param Param) *windows.SID {
	sid := param.Value.Bytes()
	if len(sid) == 0 {
		return nil
	}
	pointer := uintptr(unsafe.Pointer(&sid[0]))
	if param.Type() == params.WbemSID {
		pointer += uintptr(8 * 2)
	}
	return (*windows.SID)(unsafe.Pointer(pointer))
}

func DecodeParams(r *etw.EventRecord, e *Event) error {
	d := AcquireDecoder()
	err := d.Decode(r, e)
	ReleaseDecoder(d)
	return err
}

var paramDecoder = &ParamDecoder{}

func (e *Event) decodeParams(r *etw.EventRecord) {
	switch r.Header.ProviderID.Data1 {
	case RegistryEventGUID.Data1:
		paramDecoder.DecodeRegistry(r, e)
	case FileEventGUID.Data1:
		paramDecoder.DecodeFile(r, e)
	case StackWalkEventGUID.Data1:
		paramDecoder.DecodeStackwalk(r, e)
	case AuditAPIEventGUID.Data1:
		switch r.Header.EventDescriptor.ID {
		case OpenProcessID:
		case OpenThreadID:
			paramDecoder.DecodeOpenThread(r, e)
		case SetThreadContextID:
			paramDecoder.DecodeSetThreadContext(r, e)
		case CreateSymbolicLinkObjectID:
			paramDecoder.DecodeCreateSymbolicLinkObject(r, e)
		}
	case MemoryEventGUID.Data1:
		paramDecoder.DecodeMemory(r, e)
	case NetworkTCPEventGUID.Data1, NetworkUDPEventGUID.Data1:
		paramDecoder.DecodeNetwork(r, e)
	case DNSEventGUID.Data1:
		paramDecoder.DecodeDNS(r, e)
	case ProcessEventGUID.Data1:
		paramDecoder.DecodeProcess(r, e)
	case ModuleEventGUID.Data1:
		paramDecoder.DecodeModule(r, e)
	case ThreadEventGUID.Data1:
		paramDecoder.DecodeThread(r, e)
	case RegistryKernelEventGUID.Data1:
		paramDecoder.DecodeRegSetValueInternal(r, e)
	case ProcessKernelEventGUID.Data1:
		switch r.Header.EventDescriptor.ID {
		case CreateProcessInternalID, ProcessRundownInternalID:
			paramDecoder.DecodeProcessInternal(r, e)
		case LoadModuleInternalID:
			paramDecoder.DecodeModuleInternal(r, e)
		}
	}
}

// color applies a semantic colour to a single parameter value based
// on its type and for string types its content.
func (p Param) color() string {
	switch p.Type() {
	case params.String, params.SID:
		return colorizer.Span(colorizer.White, p.String())
	case params.Status:
		if p.String() == ntstatus.Success {
			return colorizer.Span(colorizer.Green, p.String())
		}
		return colorizer.Span(colorizer.Red, p.String())
	case params.Address:
		return colorizer.SpanDim(colorizer.Span(colorizer.Gray, "0x"+p.String()))
	case params.Int8, params.Int16, params.Int32, params.Int64,
		params.Uint8, params.Uint16, params.Uint32, params.Uint64,
		params.Float, params.Double:
		return colorizer.Span(colorizer.Yellow, p.String())
	case params.Bool:
		if p.Value.Kind() != params.KindBool {
			return colorizer.Span(colorizer.Coral, p.String())
		}
		if p.Value.Bool() {
			return colorizer.Span(colorizer.Green, p.String())
		}
		return colorizer.Span(colorizer.Coral, p.String())
	case params.IP, params.IPv4, params.IPv6:
		return colorizer.Span(colorizer.Blue, p.String())
	case params.Port:
		return colorizer.Span(colorizer.Cyan, p.String())
	case params.PID, params.TID:
		return colorizer.Span(colorizer.Green, p.String())
	default:
		return colorizer.Span(colorizer.White, p.String())
	}
}
