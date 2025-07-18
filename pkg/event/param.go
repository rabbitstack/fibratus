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

package event

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"net"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/event/params"
)

var caser = cases.Title(language.English)

// ParamCaseStyle is the type definition for parameter name case style
type ParamCaseStyle uint8

const (
	// SnakeCase is the default parameter's name case style. Multi-word parameters are delimited by underscore symbol (e.g. process_object)
	SnakeCase ParamCaseStyle = 1
	// DotCase style uses a dot to separate multi-word parameter names (e.g. process.object)
	DotCase ParamCaseStyle = 2
	// PascalCase renders parameter name with pascal case naming style (e.g. ProcessObject)
	PascalCase ParamCaseStyle = 3
	// CamelCase represents parameter names with camel case naming style (e.g. processObject)
	CamelCase ParamCaseStyle = 4
)

// ParamNameCaseStyle designates the case style for the parameter names
var ParamNameCaseStyle = SnakeCase

// ParamKVDelimiter specifies the character that delimits parameter's key from its value
var ParamKVDelimiter = "➜ "

// ParamEnum defines the type for the event parameter enumeration values. Enums
// are a direct mapping from the parameter integer value to some symbolical name
type ParamEnum map[uint32]string

type paramOpts struct {
	flags ParamFlags
	enum  ParamEnum
}

// ParamOption represents the option for the parameter literal constructor.
type ParamOption func(o *paramOpts)

// WithFlags appends the parameter with a list of bitmask flags.
func WithFlags(flags ParamFlags) ParamOption {
	return func(o *paramOpts) {
		o.flags = flags
	}
}

// WithEnum appends the parameter with the enum mapping.
func WithEnum(enum ParamEnum) ParamOption {
	return func(o *paramOpts) {
		o.enum = enum
	}
}

// Param defines the layout of the event parameter.
type Param struct {
	// Type is the type of the parameter. For example, `sport` parameter has the `Port` type although its value
	// is the uint16 numeric type.
	Type params.Type `json:"-"`
	// Value is the container for parameter values. To access the underlying value use the appropriate `Get` methods.
	Value params.Value `json:"value"`
	// Name represents the name of the parameter (e.g. pid, sport).
	Name string `json:"name"`
	// Flags represents parameter flags
	Flags ParamFlags `json:"flags"`
	// Enum represents parameter enumeration
	Enum ParamEnum `json:"enum"`
}

// CaptureType returns the event type saved inside the capture file.
// Captures usually override the type of the parameter to provide
// consistent replay experience. For example, the file path param
// type is converted to string param type, as drive mapping is performed
// on the target where the capture is being taken.
func (p Param) CaptureType() params.Type {
	switch p.Type {
	case params.HandleType, params.DOSPath, params.Key:
		return params.UnicodeString
	default:
		return p.Type
	}
}

// Params is the type that represents the sequence of event parameters
type Params map[string]*Param

// NewParamFromCapture builds a parameter instance from the restored capture state.
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

// Append adds a new parameter with the specified name, type and value.
func (pars Params) Append(name string, typ params.Type, value params.Value, opts ...ParamOption) Params {
	pars[name] = NewParam(name, typ, value, opts...)
	return pars
}

// AppendFromCapture adds a new parameter with the specified name, type and value from the cap state.
func (pars Params) AppendFromCapture(name string, typ params.Type, value params.Value, etype Type) Params {
	pars[name] = NewParamFromCapture(name, typ, value, etype)
	return pars
}

// Contains determines whether the specified parameter name exists.
func (pars Params) Contains(name string) bool {
	_, err := pars.findParam(name)
	return err == nil
}

// Remove deletes the specified parameter from the map.
func (pars Params) Remove(name string) {
	delete(pars, name)
}

// Get returns the event parameter with specified name.
func (pars Params) Get(name string) (*Param, error) {
	return pars.findParam(name)
}

// Len returns the number of parameters.
func (pars Params) Len() int { return len(pars) }

// Set replaces the value that is indexed at existing parameter name. It will return an error
// if the supplied parameter is not present.
func (pars Params) Set(name string, value params.Value, typ params.Type) error {
	_, err := pars.findParam(name)
	if err != nil {
		return fmt.Errorf("setting the value on a missing %q parameter is not allowed", name)
	}
	pars[name] = &Param{Name: name, Value: value, Type: typ}
	return nil
}

// SetValue replaces the value for the given parameter name. It will return an error
// if the supplied parameter is not present in the parameter map.
func (pars Params) SetValue(name string, value params.Value) error {
	_, err := pars.findParam(name)
	if err != nil {
		return fmt.Errorf("setting the value on a missing %q parameter is not allowed", name)
	}
	pars[name].Value = value
	return nil
}

// GetRaw returns the raw value for given parameter name. It is the responsibility of the caller to probe type assertion
// on the value before yielding its underlying type.
func (pars Params) GetRaw(name string) (params.Value, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return "", err
	}
	return par.Value, nil
}

// GetString returns the underlying string value from the parameter.
func (pars Params) GetString(name string) (string, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return "", err
	}
	if _, ok := par.Value.(string); !ok {
		return "", fmt.Errorf("unable to type cast %q parameter to string value", name)
	}
	return par.Value.(string), nil
}

// MustGetString returns the string parameter or panics
// if an error occurs while trying to get the parameter.
func (pars Params) MustGetString(name string) string {
	s, err := pars.GetString(name)
	if err != nil {
		panic(err)
	}
	return s
}

// GetPid returns the pid from the parameter.
func (pars Params) GetPid() (uint32, error) {
	return pars.getPid(params.ProcessID)
}

// MustGetPid returns the pid parameter. It panics if
// an error occurs while trying to get the pid parameter.
func (pars Params) MustGetPid() uint32 {
	pid, err := pars.GetPid()
	if err != nil {
		panic(err)
	}
	return pid
}

// GetPpid returns the parent pid from the parameter.
func (pars Params) GetPpid() (uint32, error) {
	return pars.getPid(params.ProcessParentID)
}

// MustGetPpid returns the parent pid parameter. It panics if
// an error occurs while trying to get the pid parameter.
func (pars Params) MustGetPpid() uint32 {
	ppid, err := pars.GetPpid()
	if err != nil {
		panic(err)
	}
	return ppid
}

func (pars Params) getPid(name string) (uint32, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return uint32(0), err
	}
	if par.Type != params.PID {
		return uint32(0), fmt.Errorf("%q parameter is not a PID", name)
	}
	v, ok := par.Value.(uint32)
	if !ok {
		return uint32(0), fmt.Errorf("unable to type cast %q parameter to uint32 value from pid", name)
	}
	return v, nil
}

// GetTid returns the thread id from the parameter.
func (pars Params) GetTid() (uint32, error) {
	par, err := pars.findParam(params.ThreadID)
	if err != nil {
		return uint32(0), err
	}
	if par.Type != params.TID {
		return uint32(0), fmt.Errorf("%q parameter is not a TID", params.ThreadID)
	}
	v, ok := par.Value.(uint32)
	if !ok {
		return uint32(0), fmt.Errorf("unable to type cast %q parameter to uint32 value from tid", params.ThreadID)
	}
	return v, nil
}

// MustGetTid returns the thread id from the parameter or panics if an error occurs.
func (pars Params) MustGetTid() uint32 {
	par, err := pars.findParam(params.ThreadID)
	if err != nil {
		panic(err)
	}
	if par.Type != params.TID {
		panic(fmt.Errorf("%q parameter is not a TID", params.ThreadID))
	}
	v, ok := par.Value.(uint32)
	if !ok {
		panic(fmt.Errorf("unable to type cast %q parameter to uint32 value from tid", params.ThreadID))
	}
	return v
}

// GetUint8 returns the underlying uint8 value from the parameter.
func (pars Params) GetUint8(name string) (uint8, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return uint8(0), err
	}
	v, ok := par.Value.(uint8)
	if !ok {
		return uint8(0), fmt.Errorf("unable to type cast %q parameter to uint8 value", name)
	}
	return v, nil
}

// GetBool returns the underlying boolean value from the parameter.
func (pars Params) GetBool(name string) (bool, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return false, err
	}
	v, ok := par.Value.(bool)
	if !ok {
		return false, fmt.Errorf("unable to type cast %q parameter to bool value", name)
	}
	return v, nil
}

// MustGetBool returns the underlying boolean value from the parameter or
// panics if the parameter can't be retrieved.
func (pars Params) MustGetBool(name string) bool {
	val, err := pars.GetBool(name)
	if err != nil {
		panic(err)
	}
	return val
}

// TryGetBool tries to retrieve the boolean value from the parameter.
// Returns the underlying value on success, or false otherwise.
func (pars Params) TryGetBool(name string) bool {
	val, err := pars.GetBool(name)
	if err != nil {
		return false
	}
	return val
}

// GetInt8 returns the underlying int8 value from the parameter.
func (pars Params) GetInt8(name string) (int8, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return int8(0), err
	}
	v, ok := par.Value.(int8)
	if !ok {
		return int8(0), fmt.Errorf("unable to type cast %q parameter to int8 value", name)
	}
	return v, nil
}

// GetUint16 returns the underlying int16 value from the parameter.
func (pars Params) GetUint16(name string) (uint16, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return uint16(0), err
	}
	v, ok := par.Value.(uint16)
	if !ok {
		return uint16(0), fmt.Errorf("unable to type cast %q parameter to uint16 value", name)
	}
	return v, nil
}

// MustGetUint16 returns  the underlying uint16 value parameter. It panics if
// an error occurs while trying to get the parameter.
func (pars Params) MustGetUint16(name string) uint16 {
	v, err := pars.GetUint16(name)
	if err != nil {
		panic(err)
	}
	return v
}

// TryGetUint16 tries to retrieve the uint16 value from the parameter.
// Returns the underlying value on success, or zero otherwise.
func (pars Params) TryGetUint16(name string) uint16 {
	val, err := pars.GetUint16(name)
	if err != nil {
		return 0
	}
	return val
}

// GetInt16 returns the underlying int16 value from the parameter.
func (pars Params) GetInt16(name string) (int16, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return int16(0), err
	}
	v, ok := par.Value.(int16)
	if !ok {
		return int16(0), fmt.Errorf("unable to type cast %q parameter to int16 value", name)
	}
	return v, nil
}

// GetUint32 returns the underlying uint32 value from the parameter.
func (pars Params) GetUint32(name string) (uint32, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return uint32(0), err
	}
	v, ok := par.Value.(uint32)
	if !ok {
		return uint32(0), fmt.Errorf("unable to type cast %q parameter to uint32 value", name)
	}
	return v, nil
}

// MustGetUint32 returns  the underlying uint32 value parameter. It panics if
// an error occurs while trying to get the parameter.
func (pars Params) MustGetUint32(name string) uint32 {
	v, err := pars.GetUint32(name)
	if err != nil {
		panic(err)
	}
	return v
}

// TryGetUint32 tries to retrieve the uint32 value from the parameter.
// Returns the underlying value on success, or zero otherwise.
func (pars Params) TryGetUint32(name string) uint32 {
	val, err := pars.GetUint32(name)
	if err != nil {
		return 0
	}
	return val
}

// GetInt32 returns the underlying int32 value from the parameter.
func (pars Params) GetInt32(name string) (int32, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return int32(0), err
	}
	v, ok := par.Value.(int32)
	if !ok {
		return int32(0), fmt.Errorf("unable to type cast %q parameter to int32 value", name)
	}
	return v, nil
}

// GetUint64 returns the underlying uint64 value from the parameter.
func (pars Params) GetUint64(name string) (uint64, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return uint64(0), err
	}
	v, ok := par.Value.(uint64)
	if !ok {
		return uint64(0), fmt.Errorf("unable to type cast %q parameter to uint64 value", name)
	}
	return v, nil
}

// MustGetUint64 returns  the underlying uint64 value parameter. It panics if
// an error occurs while trying to get the parameter.
func (pars Params) MustGetUint64(name string) uint64 {
	v, err := pars.GetUint64(name)
	if err != nil {
		panic(err)
	}
	return v
}

// TryGetUint64 tries to retrieve the uint64 value from the parameter.
// Returns the underlying value on success, or zero otherwise.
func (pars Params) TryGetUint64(name string) uint64 {
	val, err := pars.GetUint64(name)
	if err != nil {
		return 0
	}
	return val
}

// GetInt64 returns the underlying int64 value from the parameter.
func (pars Params) GetInt64(name string) (int64, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return int64(0), err
	}
	v, ok := par.Value.(int64)
	if !ok {
		return int64(0), fmt.Errorf("unable to type cast %q parameter to int64 value", name)
	}
	return v, nil
}

// GetFloat returns the underlying float value from the parameter.
func (pars Params) GetFloat(name string) (float32, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return float32(0), err
	}
	v, ok := par.Value.(float32)
	if !ok {
		return float32(0), fmt.Errorf("unable to type cast %q parameter to float32 value", name)
	}
	return v, nil
}

// GetDouble returns the underlying double (float64) value from the parameter.
func (pars Params) GetDouble(name string) (float64, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return float64(0), err
	}
	v, ok := par.Value.(float64)
	if !ok {
		return float64(0), fmt.Errorf("unable to type cast %q parameter to float64 value", name)
	}
	return v, nil
}

// TryGetAddress attempts to convert the underlying type to address.
func (pars Params) TryGetAddress(name string) va.Address {
	par, err := pars.findParam(name)
	if err != nil {
		return 0
	}
	v, ok := par.Value.(uint64)
	if !ok {
		return 0
	}
	return va.Address(v)
}

// GetIPv4 returns the underlying IPv4 address from the parameter.
func (pars Params) GetIPv4(name string) (net.IP, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return net.IP{}, err
	}
	if par.Type != params.IPv4 {
		return net.IP{}, fmt.Errorf("%q parameter is not an IPv4 address", name)
	}
	v, ok := par.Value.(net.IP)
	if !ok {
		return net.IP{}, fmt.Errorf("unable to type cast %q parameter to net.IP value", name)
	}
	return v, nil
}

// GetIPv6 returns the underlying IPv6 address from the parameter.
func (pars Params) GetIPv6(name string) (net.IP, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return net.IP{}, err
	}
	if par.Type != params.IPv6 {
		return net.IP{}, fmt.Errorf("%q parameter is not an IPv6 address", name)
	}
	v, ok := par.Value.(net.IP)
	if !ok {
		return net.IP{}, fmt.Errorf("unable to type cast %q parameter to net.IP value", name)
	}
	return v, nil
}

// GetIP returns either the IPv4 or IPv6 address from the parameter.
func (pars Params) GetIP(name string) (net.IP, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return net.IP{}, err
	}
	if par.Type != params.IPv4 && par.Type != params.IPv6 {
		return net.IP{}, fmt.Errorf("%q parameter is not an IP address", name)
	}
	v, ok := par.Value.(net.IP)
	if !ok {
		return net.IP{}, fmt.Errorf("unable to type cast %q parameter to net.IP value", name)
	}
	return v, nil
}

// MustGetIP returns the IP address parameter or panics if an error occurs.
func (pars Params) MustGetIP(name string) net.IP {
	ip, err := pars.GetIP(name)
	if err != nil {
		panic(err)
	}
	return ip
}

// GetTime returns the underlying time structure from the parameter.
func (pars Params) GetTime(name string) (time.Time, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return time.Unix(0, 0), err
	}
	v, ok := par.Value.(time.Time)
	if !ok {
		return time.Unix(0, 0), fmt.Errorf("unable to type cast %q parameter to Time value", name)
	}
	return v, nil
}

// MustGetTime returns the underlying time structure from the parameter or panics
// if any errors occur.
func (pars Params) MustGetTime(name string) time.Time {
	par, err := pars.findParam(name)
	if err != nil {
		panic(err)
	}
	v, ok := par.Value.(time.Time)
	if !ok {
		panic(fmt.Errorf("unable to type cast %q parameter to Time value", name))
	}
	return v
}

// GetStringSlice returns the string slice from the event parameter.
func (pars Params) GetStringSlice(name string) ([]string, error) {
	par, err := pars.GetSlice(name)
	if err != nil {
		return nil, err
	}
	v, ok := par.([]string)
	if !ok {
		return nil, fmt.Errorf("unable to type cast %q parameter to string slice", name)
	}
	return v, nil
}

// GetSlice returns the slice of generic values from the parameter.
func (pars Params) GetSlice(name string) (params.Value, error) {
	par, err := pars.findParam(name)
	if err != nil {
		return nil, err
	}
	if reflect.TypeOf(par.Value).Kind() != reflect.Slice {
		return nil, fmt.Errorf("%q parameter is not a slice", name)
	}
	return par.Value, nil
}

// MustGetSlice returns the slice of generic values from the parameter or
// panics if the parameter cannot be found.
func (pars Params) MustGetSlice(name string) params.Value {
	par, err := pars.findParam(name)
	if err != nil {
		panic(err)
	}
	return par.Value
}

// MustGetSliceAddrs returns the slice of addresses or panics if the parameter
// is not found, or either a parameter is not a slice of addresses.
func (pars Params) MustGetSliceAddrs(name string) []va.Address {
	val := pars.MustGetSlice(name)
	addrs, ok := val.([]va.Address)
	if !ok {
		panic("must be a slice of addresses")
	}
	return addrs
}

// String returns the string representation of the event parameters. Parameter names are rendered according
// to the currently active parameter style case.
func (pars Params) String() string {
	var sb strings.Builder
	// sort parameters by name
	s := make([]*Param, 0, len(pars))
	for _, par := range pars {
		s = append(s, par)
	}
	sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	for i, par := range s {
		switch ParamNameCaseStyle {
		case SnakeCase:
			sb.WriteString(par.Name + ParamKVDelimiter + par.String())
		case DotCase:
			sb.WriteString(strings.ReplaceAll(par.Name, "_", ".") + ParamKVDelimiter + par.String())
		case PascalCase:
			sb.WriteString(strings.ReplaceAll(caser.String(strings.ReplaceAll(par.Name, "_", " ")), " ", "") + ParamKVDelimiter + par.String())
		case CamelCase:
		}
		if i != len(pars)-1 {
			sb.WriteString(", ")
		}
	}
	return sb.String()
}

// Find returns the parameter with the specified name. If it is not found, nil value is returned.
func (pars Params) Find(name string) *Param {
	par, err := pars.findParam(name)
	if err != nil {
		return nil
	}
	return par
}

// findParam lookups a parameter in the map and returns an error if it doesn't exist.
func (pars Params) findParam(name string) (*Param, error) {
	if _, ok := pars[name]; !ok {
		return nil, &errors.ErrParamNotFound{Name: name}
	}
	return pars[name], nil
}
