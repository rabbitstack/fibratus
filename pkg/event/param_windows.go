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
	"net"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/ip"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/rabbitstack/fibratus/pkg/util/ntstatus"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
)

// unknownKeysCount counts the number of times the registry key failed to convert from native format
var unknownKeysCount = expvar.NewInt("registry.unknown.keys.count")

// NewParam creates a new event parameter. Since the parameter type is already categorized,
// we can coerce the value to the appropriate representation (e.g. hex, IP address)
func NewParam(name string, typ params.Type, value params.Value, options ...ParamOption) *Param {
	var opts paramOpts
	for _, opt := range options {
		opt(&opts)
	}
	var v params.Value
	switch typ {
	case params.IPv4:
		v = ip.ToIPv4(value.(uint32))
	case params.IPv6:
		v = ip.ToIPv6(value.([]byte))
	case params.Port:
		v = windows.Ntohs(value.(uint16))
	default:
		v = value
	}
	return &Param{Name: name, Type: typ, Value: v, Flags: opts.flags, Enum: opts.enum}
}

// String returns the string representation of the parameter value.
func (p Param) String() string {
	if p.Value == nil {
		return ""
	}
	switch p.Type {
	case params.UnicodeString, params.AnsiString, params.Path:
		return p.Value.(string)
	case params.SID, params.WbemSID:
		sid, err := getSID(&p)
		if err != nil {
			return ""
		}
		if p.Name == params.ProcessTokenIntegrityLevel {
			return sys.RidToString(sid)
		}
		return sid.String()
	case params.DOSPath:
		return fs.GetDevMapper().Convert(p.Value.(string))
	case params.Key:
		rootKey, keyName := key.Format(p.Value.(string))
		if keyName != "" && rootKey != key.Invalid {
			return rootKey.String() + "\\" + keyName
		}
		if rootKey != key.Invalid {
			return rootKey.String()
		}
		unknownKeysCount.Add(1)
		return keyName
	case params.HandleType:
		return htypes.ConvertTypeIDToName(p.Value.(uint16))
	case params.Status:
		v, ok := p.Value.(uint32)
		if !ok {
			return ""
		}
		return ntstatus.FormatMessage(v)
	case params.Address:
		v, ok := p.Value.(uint64)
		if !ok {
			return ""
		}
		return va.Address(v).String()
	case params.Int8:
		return strconv.Itoa(int(p.Value.(int8)))
	case params.Uint8:
		return strconv.Itoa(int(p.Value.(uint8)))
	case params.Int16:
		return strconv.Itoa(int(p.Value.(int16)))
	case params.Uint16, params.Port:
		return strconv.Itoa(int(p.Value.(uint16)))
	case params.Uint32, params.PID, params.TID:
		return strconv.Itoa(int(p.Value.(uint32)))
	case params.Int32:
		return strconv.Itoa(int(p.Value.(int32)))
	case params.Uint64:
		return strconv.FormatUint(p.Value.(uint64), 10)
	case params.Int64:
		return strconv.Itoa(int(p.Value.(int64)))
	case params.IPv4, params.IPv6:
		return p.Value.(net.IP).String()
	case params.Bool:
		return strconv.FormatBool(p.Value.(bool))
	case params.Float:
		return strconv.FormatFloat(float64(p.Value.(float32)), 'f', 6, 32)
	case params.Double:
		return strconv.FormatFloat(p.Value.(float64), 'f', 6, 64)
	case params.Time:
		return p.Value.(time.Time).String()
	case params.Enum:
		if p.Enum == nil {
			return ""
		}
		e := p.Value
		v, ok := e.(uint32)
		if !ok {
			return ""
		}
		return p.Enum[v]
	case params.Flags, params.Flags64:
		if p.Flags == nil {
			return ""
		}
		f := p.Value
		switch v := f.(type) {
		case uint32:
			return p.Flags.String(uint64(v))
		case uint64:
			return p.Flags.String(v)
		default:
			return ""
		}
	case params.Slice:
		switch slice := p.Value.(type) {
		case []string:
			return strings.Join(slice, ",")
		default:
			return fmt.Sprintf("%v", slice)
		}
	case params.Binary:
		return string(p.Value.([]byte))
	}
	return fmt.Sprintf("%v", p.Value)
}

// GetSID returns the raw SID (Security Identifier) parameter as
// typed representation on which various operations can be performed,
// such as converting the SID to string or resolving username/domain.
func (pars Params) GetSID() (*windows.SID, error) {
	par, err := pars.findParam(params.UserSID)
	if err != nil {
		return nil, err
	}
	return getSID(par)
}

func getSID(param *Param) (*windows.SID, error) {
	sid, ok := param.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("unable to type cast %q parameter to []byte value", param.Name)
	}
	if sid == nil {
		return nil, fmt.Errorf("sid linked to parameter %s is empty", param.Name)
	}
	b := uintptr(unsafe.Pointer(&sid[0]))
	if param.Type == params.WbemSID {
		// a WBEM SID is actually a TOKEN_USER structure followed
		// by the SID, so we have to double the pointer size
		b += uintptr(8 * 2)
	}
	return (*windows.SID)(unsafe.Pointer(b)), nil
}

// MustGetSID returns the SID (Security Identifier) event parameter
// or panics if an error occurs.
func (pars Params) MustGetSID() *windows.SID {
	sid, err := pars.GetSID()
	if err != nil {
		panic(err)
	}
	return sid
}

var paramDecoder = &ParamDecoder{}

// decodeParams parses the event binary layout to extract
// the parameters. Each event is annotated with the schema
// version number which helps us determine when the event
// schema changes in order to parse new fields.
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
