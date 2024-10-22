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

package kevent

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
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

	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
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

// ParamNameCaseStyle designates the case style for kernel parameter names
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

// Kparam defines the layout of the kernel event parameter.
type Kparam struct {
	// Type is the type of the parameter. For example, `sport` parameter has the `Port` type although its value
	// is the uint16 numeric type.
	Type kparams.Type `json:"-"`
	// Value is the container for parameter values. To access the underlying value use the appropriate `Get` methods.
	Value kparams.Value `json:"value"`
	// Name represents the name of the parameter (e.g. pid, sport).
	Name string `json:"name"`
	// Flags represents parameter flags
	Flags ParamFlags `json:"flags"`
	// Enum represents parameter enumeration
	Enum ParamEnum `json:"enum"`
}

// KcapType returns the event type saved inside the capture file.
// Captures usually override the type of the parameter to provide
// consistent replay experience. For example, the file path param
// type is converted to string param type, as drive mapping is performed
// on the target where the capture is being taken.
func (k Kparam) KcapType() kparams.Type {
	switch k.Type {
	case kparams.HandleType, kparams.FileDosPath, kparams.Key:
		return kparams.UnicodeString
	default:
		return k.Type
	}
}

// Kparams is the type that represents the sequence of kernel event parameters
type Kparams map[string]*Kparam

// NewKparamFromKcap builds a kparam instance from the restored state.
func NewKparamFromKcap(name string, typ kparams.Type, value kparams.Value, ktype ktypes.Ktype) *Kparam {
	var enum ParamEnum
	var flags ParamFlags
	switch name {
	case kparams.FileOperation:
		enum = fs.FileCreateDispositions
	case kparams.FileCreateOptions:
		flags = FileCreateOptionsFlags
	case kparams.FileAttributes:
		flags = FileAttributeFlags
	case kparams.FileShareMask:
		flags = FileShareModeFlags
	case kparams.FileInfoClass:
		enum = fs.FileInfoClasses
	case kparams.FileType:
		enum = fs.FileTypes
	case kparams.NetL4Proto:
		enum = network.ProtoNames
	case kparams.RegValueType:
		enum = key.RegistryValueTypes
	case kparams.MemAllocType:
		flags = MemAllocationFlags
	case kparams.FileViewSectionType:
		enum = ViewSectionTypes
	case kparams.DNSOpts:
		flags = DNSOptsFlags
	case kparams.DNSRR:
		enum = DNSRecordTypes
	case kparams.DNSRcode:
		enum = DNSResponseCodes
	case kparams.DesiredAccess:
		if ktype == ktypes.OpenProcess {
			flags = PsAccessRightFlags
		} else {
			flags = ThreadAccessRightFlags
		}
	case kparams.MemProtect:
		if ktype == ktypes.VirtualAlloc || ktype == ktypes.VirtualFree {
			flags = MemProtectionFlags
		} else {
			flags = ViewProtectionFlags
		}
	}
	return &Kparam{Name: name, Type: typ, Value: value, Enum: enum, Flags: flags}
}

// Append adds a new parameter with the specified name, type and value.
func (kpars Kparams) Append(name string, typ kparams.Type, value kparams.Value, opts ...ParamOption) Kparams {
	kpars[name] = NewKparam(name, typ, value, opts...)
	return kpars
}

// AppendFromKcap adds a new parameter with the specified name, type and value from the kcap state.
func (kpars Kparams) AppendFromKcap(name string, typ kparams.Type, value kparams.Value, ktype ktypes.Ktype) Kparams {
	kpars[name] = NewKparamFromKcap(name, typ, value, ktype)
	return kpars
}

// Contains determines whether the specified parameter name exists.
func (kpars Kparams) Contains(name string) bool {
	_, err := kpars.findParam(name)
	return err == nil
}

// Remove deletes the specified parameter from the map.
func (kpars Kparams) Remove(name string) {
	delete(kpars, name)
}

// Get returns the event parameter with specified name.
func (kpars Kparams) Get(name string) (*Kparam, error) {
	return kpars.findParam(name)
}

// Len returns the number of parameters.
func (kpars Kparams) Len() int { return len(kpars) }

// Set replaces the value that is indexed at existing parameter name. It will return an error
// if the supplied parameter is not present.
func (kpars Kparams) Set(name string, value kparams.Value, typ kparams.Type) error {
	_, err := kpars.findParam(name)
	if err != nil {
		return fmt.Errorf("setting the value on a missing %q parameter is not allowed", name)
	}
	kpars[name] = &Kparam{Name: name, Value: value, Type: typ}
	return nil
}

// SetValue replaces the value for the given parameter name. It will return an error
// if the supplied parameter is not present in the parameter map.
func (kpars Kparams) SetValue(name string, value kparams.Value) error {
	_, err := kpars.findParam(name)
	if err != nil {
		return fmt.Errorf("setting the value on a missing %q parameter is not allowed", name)
	}
	kpars[name].Value = value
	return nil
}

// GetRaw returns the raw value for given parameter name. It is the responsibility of the caller to probe type assertion
// on the value before yielding its underlying type.
func (kpars Kparams) GetRaw(name string) (kparams.Value, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return "", err
	}
	return kpar.Value, nil
}

// GetString returns the underlying string value from the parameter.
func (kpars Kparams) GetString(name string) (string, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return "", err
	}
	if _, ok := kpar.Value.(string); !ok {
		return "", fmt.Errorf("unable to type cast %q parameter to string value", name)
	}
	return kpar.Value.(string), nil
}

// MustGetString returns the string parameter or panics
// if an error occurs while trying to get the parameter.
func (kpars Kparams) MustGetString(name string) string {
	s, err := kpars.GetString(name)
	if err != nil {
		panic(err)
	}
	return s
}

// GetPid returns the pid from the parameter.
func (kpars Kparams) GetPid() (uint32, error) {
	return kpars.getPid(kparams.ProcessID)
}

// MustGetPid returns the pid parameter. It panics if
// an error occurs while trying to get the pid parameter.
func (kpars Kparams) MustGetPid() uint32 {
	pid, err := kpars.GetPid()
	if err != nil {
		panic(err)
	}
	return pid
}

// GetPpid returns the parent pid from the parameter.
func (kpars Kparams) GetPpid() (uint32, error) {
	return kpars.getPid(kparams.ProcessParentID)
}

// MustGetPpid returns the parent pid parameter. It panics if
// an error occurs while trying to get the pid parameter.
func (kpars Kparams) MustGetPpid() uint32 {
	ppid, err := kpars.GetPpid()
	if err != nil {
		panic(err)
	}
	return ppid
}

func (kpars Kparams) getPid(name string) (uint32, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return uint32(0), err
	}
	if kpar.Type != kparams.PID {
		return uint32(0), fmt.Errorf("%q parameter is not a PID", name)
	}
	v, ok := kpar.Value.(uint32)
	if !ok {
		return uint32(0), fmt.Errorf("unable to type cast %q parameter to uint32 value from pid", name)
	}
	return v, nil
}

// GetTid returns the thread id from the parameter.
func (kpars Kparams) GetTid() (uint32, error) {
	kpar, err := kpars.findParam(kparams.ThreadID)
	if err != nil {
		return uint32(0), err
	}
	if kpar.Type != kparams.TID {
		return uint32(0), fmt.Errorf("%q parameter is not a TID", kparams.ThreadID)
	}
	v, ok := kpar.Value.(uint32)
	if !ok {
		return uint32(0), fmt.Errorf("unable to type cast %q parameter to uint32 value from tid", kparams.ThreadID)
	}
	return v, nil
}

// MustGetTid returns the thread id from the parameter or panics if an error occurs.
func (kpars Kparams) MustGetTid() uint32 {
	kpar, err := kpars.findParam(kparams.ThreadID)
	if err != nil {
		panic(err)
	}
	if kpar.Type != kparams.TID {
		panic(fmt.Errorf("%q parameter is not a TID", kparams.ThreadID))
	}
	v, ok := kpar.Value.(uint32)
	if !ok {
		panic(fmt.Errorf("unable to type cast %q parameter to uint32 value from tid", kparams.ThreadID))
	}
	return v
}

// GetUint8 returns the underlying uint8 value from the parameter.
func (kpars Kparams) GetUint8(name string) (uint8, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return uint8(0), err
	}
	v, ok := kpar.Value.(uint8)
	if !ok {
		return uint8(0), fmt.Errorf("unable to type cast %q parameter to uint8 value", name)
	}
	return v, nil
}

// GetBool returns the underlying boolean value from the parameter.
func (kpars Kparams) GetBool(name string) (bool, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return false, err
	}
	v, ok := kpar.Value.(bool)
	if !ok {
		return false, fmt.Errorf("unable to type cast %q parameter to bool value", name)
	}
	return v, nil
}

// TryGetBool tries to retrieve the boolean value from the parameter.
// Returns the underlying value on success, or false otherwise.
func (kpars Kparams) TryGetBool(name string) bool {
	val, err := kpars.GetBool(name)
	if err != nil {
		return false
	}
	return val
}

// GetInt8 returns the underlying int8 value from the parameter.
func (kpars Kparams) GetInt8(name string) (int8, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return int8(0), err
	}
	v, ok := kpar.Value.(int8)
	if !ok {
		return int8(0), fmt.Errorf("unable to type cast %q parameter to int8 value", name)
	}
	return v, nil
}

// GetUint16 returns the underlying int16 value from the parameter.
func (kpars Kparams) GetUint16(name string) (uint16, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return uint16(0), err
	}
	v, ok := kpar.Value.(uint16)
	if !ok {
		return uint16(0), fmt.Errorf("unable to type cast %q parameter to uint16 value", name)
	}
	return v, nil
}

// MustGetUint16 returns  the underlying uint16 value parameter. It panics if
// an error occurs while trying to get the parameter.
func (kpars Kparams) MustGetUint16(name string) uint16 {
	v, err := kpars.GetUint16(name)
	if err != nil {
		panic(err)
	}
	return v
}

// TryGetUint16 tries to retrieve the uint16 value from the parameter.
// Returns the underlying value on success, or zero otherwise.
func (kpars Kparams) TryGetUint16(name string) uint16 {
	val, err := kpars.GetUint16(name)
	if err != nil {
		return 0
	}
	return val
}

// GetInt16 returns the underlying int16 value from the parameter.
func (kpars Kparams) GetInt16(name string) (int16, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return int16(0), err
	}
	v, ok := kpar.Value.(int16)
	if !ok {
		return int16(0), fmt.Errorf("unable to type cast %q parameter to int16 value", name)
	}
	return v, nil
}

// GetUint32 returns the underlying uint32 value from the parameter.
func (kpars Kparams) GetUint32(name string) (uint32, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return uint32(0), err
	}
	v, ok := kpar.Value.(uint32)
	if !ok {
		return uint32(0), fmt.Errorf("unable to type cast %q parameter to uint32 value", name)
	}
	return v, nil
}

// MustGetUint32 returns  the underlying uint32 value parameter. It panics if
// an error occurs while trying to get the parameter.
func (kpars Kparams) MustGetUint32(name string) uint32 {
	v, err := kpars.GetUint32(name)
	if err != nil {
		panic(err)
	}
	return v
}

// TryGetUint32 tries to retrieve the uint32 value from the parameter.
// Returns the underlying value on success, or zero otherwise.
func (kpars Kparams) TryGetUint32(name string) uint32 {
	val, err := kpars.GetUint32(name)
	if err != nil {
		return 0
	}
	return val
}

// GetInt32 returns the underlying int32 value from the parameter.
func (kpars Kparams) GetInt32(name string) (int32, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return int32(0), err
	}
	v, ok := kpar.Value.(int32)
	if !ok {
		return int32(0), fmt.Errorf("unable to type cast %q parameter to int32 value", name)
	}
	return v, nil
}

// GetUint64 returns the underlying uint64 value from the parameter.
func (kpars Kparams) GetUint64(name string) (uint64, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return uint64(0), err
	}
	v, ok := kpar.Value.(uint64)
	if !ok {
		return uint64(0), fmt.Errorf("unable to type cast %q parameter to uint64 value", name)
	}
	return v, nil
}

// MustGetUint64 returns  the underlying uint64 value parameter. It panics if
// an error occurs while trying to get the parameter.
func (kpars Kparams) MustGetUint64(name string) uint64 {
	v, err := kpars.GetUint64(name)
	if err != nil {
		panic(err)
	}
	return v
}

// TryGetUint64 tries to retrieve the uint64 value from the parameter.
// Returns the underlying value on success, or zero otherwise.
func (kpars Kparams) TryGetUint64(name string) uint64 {
	val, err := kpars.GetUint64(name)
	if err != nil {
		return 0
	}
	return val
}

// GetInt64 returns the underlying int64 value from the parameter.
func (kpars Kparams) GetInt64(name string) (int64, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return int64(0), err
	}
	v, ok := kpar.Value.(int64)
	if !ok {
		return int64(0), fmt.Errorf("unable to type cast %q parameter to int64 value", name)
	}
	return v, nil
}

// GetFloat returns the underlying float value from the parameter.
func (kpars Kparams) GetFloat(name string) (float32, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return float32(0), err
	}
	v, ok := kpar.Value.(float32)
	if !ok {
		return float32(0), fmt.Errorf("unable to type cast %q parameter to float32 value", name)
	}
	return v, nil
}

// GetDouble returns the underlying double (float64) value from the parameter.
func (kpars Kparams) GetDouble(name string) (float64, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return float64(0), err
	}
	v, ok := kpar.Value.(float64)
	if !ok {
		return float64(0), fmt.Errorf("unable to type cast %q parameter to float64 value", name)
	}
	return v, nil
}

// TryGetAddress attempts to convert the underlying type to address.
func (kpars Kparams) TryGetAddress(name string) va.Address {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return 0
	}
	v, ok := kpar.Value.(uint64)
	if !ok {
		return 0
	}
	return va.Address(v)
}

// GetIPv4 returns the underlying IPv4 address from the parameter.
func (kpars Kparams) GetIPv4(name string) (net.IP, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return net.IP{}, err
	}
	if kpar.Type != kparams.IPv4 {
		return net.IP{}, fmt.Errorf("%q parameter is not an IPv4 address", name)
	}
	v, ok := kpar.Value.(net.IP)
	if !ok {
		return net.IP{}, fmt.Errorf("unable to type cast %q parameter to net.IP value", name)
	}
	return v, nil
}

// GetIPv6 returns the underlying IPv6 address from the parameter.
func (kpars Kparams) GetIPv6(name string) (net.IP, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return net.IP{}, err
	}
	if kpar.Type != kparams.IPv6 {
		return net.IP{}, fmt.Errorf("%q parameter is not an IPv6 address", name)
	}
	v, ok := kpar.Value.(net.IP)
	if !ok {
		return net.IP{}, fmt.Errorf("unable to type cast %q parameter to net.IP value", name)
	}
	return v, nil
}

// GetIP returns either the IPv4 or IPv6 address from the parameter.
func (kpars Kparams) GetIP(name string) (net.IP, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return net.IP{}, err
	}
	if kpar.Type != kparams.IPv4 && kpar.Type != kparams.IPv6 {
		return net.IP{}, fmt.Errorf("%q parameter is not an IP address", name)
	}
	v, ok := kpar.Value.(net.IP)
	if !ok {
		return net.IP{}, fmt.Errorf("unable to type cast %q parameter to net.IP value", name)
	}
	return v, nil
}

// MustGetIP returns the IP address parameter or panics if an error occurs.
func (kpars Kparams) MustGetIP(name string) net.IP {
	ip, err := kpars.GetIP(name)
	if err != nil {
		panic(err)
	}
	return ip
}

// GetTime returns the underlying time structure from the parameter.
func (kpars Kparams) GetTime(name string) (time.Time, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return time.Unix(0, 0), err
	}
	v, ok := kpar.Value.(time.Time)
	if !ok {
		return time.Unix(0, 0), fmt.Errorf("unable to type cast %q parameter to Time value", name)
	}
	return v, nil
}

// MustGetTime returns the underlying time structure from the parameter or panics
// if any errors occur.
func (kpars Kparams) MustGetTime(name string) time.Time {
	kpar, err := kpars.findParam(name)
	if err != nil {
		panic(err)
	}
	v, ok := kpar.Value.(time.Time)
	if !ok {
		panic(fmt.Errorf("unable to type cast %q parameter to Time value", name))
	}
	return v
}

// GetStringSlice returns the string slice from the event parameter.
func (kpars Kparams) GetStringSlice(name string) ([]string, error) {
	kpar, err := kpars.GetSlice(name)
	if err != nil {
		return nil, err
	}
	v, ok := kpar.([]string)
	if !ok {
		return nil, fmt.Errorf("unable to type cast %q parameter to string slice", name)
	}
	return v, nil
}

// GetSlice returns the slice of generic values from the parameter.
func (kpars Kparams) GetSlice(name string) (kparams.Value, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return nil, err
	}
	if reflect.TypeOf(kpar.Value).Kind() != reflect.Slice {
		return nil, fmt.Errorf("%q parameter is not a slice", name)
	}
	return kpar.Value, nil
}

// MustGetSlice returns the slice of generic values from the parameter or
// panics if the parameter cannot be found.
func (kpars Kparams) MustGetSlice(name string) kparams.Value {
	kpar, err := kpars.findParam(name)
	if err != nil {
		panic(err)
	}
	return kpar.Value
}

// MustGetSliceAddrs returns the slice of addresses or panics if the parameter
// is not found, or either a parameter is not a slice of addresses.
func (kpars Kparams) MustGetSliceAddrs(name string) []va.Address {
	val := kpars.MustGetSlice(name)
	addrs, ok := val.([]va.Address)
	if !ok {
		panic("must be a slice of addresses")
	}
	return addrs
}

// String returns the string representation of the event parameters. Parameter names are rendered according
// to the currently active parameter style case.
func (kpars Kparams) String() string {
	var sb strings.Builder
	// sort parameters by name
	pars := make([]*Kparam, 0, len(kpars))
	for _, kpar := range kpars {
		pars = append(pars, kpar)
	}
	sort.Slice(pars, func(i, j int) bool { return pars[i].Name < pars[j].Name })
	for i, kpar := range pars {
		switch ParamNameCaseStyle {
		case SnakeCase:
			sb.WriteString(kpar.Name + ParamKVDelimiter + kpar.String())
		case DotCase:
			sb.WriteString(strings.Replace(kpar.Name, "_", ".", -1) + ParamKVDelimiter + kpar.String())
		case PascalCase:
			sb.WriteString(strings.Replace(caser.String(strings.Replace(kpar.Name, "_", " ", -1)), " ", "", -1) + ParamKVDelimiter + kpar.String())
		case CamelCase:
		}
		if i != len(pars)-1 {
			sb.WriteString(", ")
		}
	}
	return sb.String()
}

// Find returns the kparam with specified name. If it is not found, nil value is returned.
func (kpars Kparams) Find(name string) *Kparam {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return nil
	}
	return kpar
}

// findParam lookups a parameter in the map and returns an error if it doesn't exist.
func (kpars Kparams) findParam(name string) (*Kparam, error) {
	if _, ok := kpars[name]; !ok {
		return nil, &kerrors.ErrKparamNotFound{Name: name}
	}
	return kpars[name], nil
}
