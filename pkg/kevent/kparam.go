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
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/syscall/security"
	"github.com/rabbitstack/fibratus/pkg/util/ip"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var kparamPool = sync.Pool{
	New: func() interface{} {
		return &Kparam{}
	},
}

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

// Kparam defines the layout of the kernel event parameter.
type Kparam struct {
	// Type is the type of the parameter. For example, `sport` parameter has the `Port` type although its value
	// is the uint16 numeric type.
	Type kparams.Type `json:"-"`
	// Value is the container for parameter values. To access the underlying value use the appropriate `Get` methods.
	Value kparams.Value `json:"value"`
	// Name represents the name of the parameter (e.g. pid, sport).
	Name string `json:"name"`
}

// Kparams is the type that represents the sequence of kernel event parameters
type Kparams map[string]*Kparam

// NewKparam creates a new event parameter. Since the parameter type is already categorized,
// we can coerce the value to the appropriate representation (e.g. hex, IP address, user security identifier, etc.)
func NewKparam(name string, typ kparams.Type, value kparams.Value) *Kparam {
	var v kparams.Value
	switch typ {
	case kparams.HexInt8, kparams.HexInt16, kparams.HexInt32, kparams.HexInt64:
		v = kparams.NewHex(value)

	case kparams.IPv4:
		v = ip.ToIPv4(value.(uint32))

	case kparams.IPv6:
		v = ip.ToIPv6(value.([]byte))

	case kparams.Port:
		v = syscall.Ntohs(value.(uint16))

	case kparams.SID:
		account, domain := security.LookupAccount(value.([]byte), false)
		if account != "" || domain != "" {
			v = joinSID(account, domain)
		}

	case kparams.WbemSID:
		account, domain := security.LookupAccount(value.([]byte), true)
		if account != "" || domain != "" {
			v = joinSID(account, domain)
		}

	default:
		v = value
	}

	kparam := kparamPool.Get().(*Kparam)
	*kparam = Kparam{Name: name, Type: typ, Value: v}

	return kparam
}

// NewKparamFromKcap builds a kparam instance from the restored state.
func NewKparamFromKcap(name string, typ kparams.Type, value kparams.Value) *Kparam {
	return &Kparam{Name: name, Type: typ, Value: value}
}

// String returns the string representation of the parameter value.
func (k Kparam) String() string {
	if k.Value == nil {
		return ""
	}
	switch k.Type {
	case kparams.UnicodeString, kparams.AnsiString, kparams.SID, kparams.WbemSID:
		return k.Value.(string)
	case kparams.HexInt32, kparams.HexInt64, kparams.HexInt16, kparams.HexInt8:
		return string(k.Value.(kparams.Hex))
	case kparams.Int8:
		return strconv.Itoa(int(k.Value.(int8)))
	case kparams.Uint8:
		return strconv.Itoa(int(k.Value.(uint8)))
	case kparams.Int16:
		return strconv.Itoa(int(k.Value.(int16)))
	case kparams.Uint16, kparams.Port:
		return strconv.Itoa(int(k.Value.(uint16)))
	case kparams.Uint32, kparams.PID, kparams.TID:
		return strconv.Itoa(int(k.Value.(uint32)))
	case kparams.Int32:
		return strconv.Itoa(int(k.Value.(int32)))
	case kparams.Uint64:
		return strconv.FormatUint(k.Value.(uint64), 10)
	case kparams.Int64:
		return strconv.Itoa(int(k.Value.(int64)))
	case kparams.IPv4, kparams.IPv6:
		return k.Value.(net.IP).String()
	case kparams.Bool:
		return strconv.FormatBool(k.Value.(bool))
	case kparams.Float:
		return strconv.FormatFloat(float64(k.Value.(float32)), 'f', 6, 32)
	case kparams.Double:
		return strconv.FormatFloat(k.Value.(float64), 'f', 6, 64)
	case kparams.Time:
		return k.Value.(time.Time).String()
	case kparams.Enum:
		switch typ := k.Value.(type) {
		case fs.FileShareMode:
			return typ.String()
		case network.L4Proto:
			return typ.String()
		case fs.FileDisposition:
			return typ.String()
		default:
			return fmt.Sprintf("%v", k.Value)
		}
	default:
		return fmt.Sprintf("%v", k.Value)
	}
}

// Release returns the param to the pool.
func (k *Kparam) Release() {
	kparamPool.Put(k)
}

// Append adds a new parameter with specified name, type and value.
func (kpars Kparams) Append(name string, typ kparams.Type, value kparams.Value) Kparams {
	kpars[name] = NewKparam(name, typ, value)
	return kpars
}

// AppendFromKcap adds a new parameter with specified name, type and value from the kcap state.
func (kpars Kparams) AppendFromKcap(name string, typ kparams.Type, value kparams.Value) Kparams {
	kpars[name] = NewKparamFromKcap(name, typ, value)
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

// Get returns the raw value for given parameter name. It is the responsibility of the caller to probe type assertion
// on the value before yielding its underlying type.
func (kpars Kparams) Get(name string) (kparams.Value, error) {
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

// GetPid returns the pid from the parameter.
func (kpars Kparams) GetPid() (uint32, error) {
	return kpars.getPid(kparams.ProcessID)
}

// GetPpid returns the parent pid from the parameter.
func (kpars Kparams) GetPpid() (uint32, error) {
	return kpars.getPid(kparams.ProcessParentID)
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

// GetHexAsUint32 returns the number hexadecimal representation as uint32 value.
func (kpars Kparams) GetHexAsUint32(name string) (uint32, error) {
	hex, err := kpars.GetHex(name)
	if err != nil {
		return uint32(0), err
	}
	return hex.Uint32(), nil
}

// GetHexAsUint8 returns the number hexadecimal representation as uint8 value.
func (kpars Kparams) GetHexAsUint8(name string) (uint8, error) {
	hex, err := kpars.GetHex(name)
	if err != nil {
		return uint8(0), err
	}
	return hex.Uint8(), nil
}

// GetHexAsUint64 returns the number hexadecimal representation as uint64 value.
func (kpars Kparams) GetHexAsUint64(name string) (uint64, error) {
	hex, err := kpars.GetHex(name)
	if err != nil {
		return uint64(0), err
	}
	return hex.Uint64(), nil
}

// GetHex returns the generic hexadecimal type for the specified parameter name.
func (kpars Kparams) GetHex(name string) (kparams.Hex, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return "", err
	}
	v, ok := kpar.Value.(kparams.Hex)
	if !ok {
		return "", fmt.Errorf("unable to type cast %q parameter to Hex value", name)
	}
	return v, nil
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

// GetStringSlice returns the string slice from the event parameter.
func (kpars Kparams) GetStringSlice(name string) ([]string, error) {
	kpar, err := kpars.findParam(name)
	if err != nil {
		return nil, err
	}
	v, ok := kpar.Value.([]string)
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
			sb.WriteString(strings.Replace(strings.Title(strings.Replace(kpar.Name, "_", " ", -1)), " ", "", -1) + ParamKVDelimiter + kpar.String())
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

func joinSID(account, domain string) string { return fmt.Sprintf("%s\\%s", domain, account) }
