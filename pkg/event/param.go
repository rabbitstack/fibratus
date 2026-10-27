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
	"net"
	"strings"
	"time"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
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

// Param is the event parameter. It contains only the value of the
// parameter and a reference to the descriptor in the event table that
// provides the name, type, flags, and enumeration of the parameter.
// An absent parameter has the null value.
type Param struct {
	// Value is the container for parameter values. It is a tagged union, so
	// the value is stored without boxing it into an interface.
	Value params.Value
	info  *params.ParamInfo
}

// Name returns the parameter name.
func (p Param) Name() string {
	if p.info == nil {
		return ""
	}
	return p.info.Name
}

// Type returns the logical parameter type.
func (p Param) Type() params.Type {
	if p.info == nil {
		return params.Null
	}
	return p.info.Type
}

// Flags returns the bitmask flags of the parameter.
func (p Param) Flags() params.Flags {
	if p.info == nil {
		return nil
	}
	return p.info.Flags
}

// Enum returns the enumeration of the parameter.
func (p Param) Enum() params.Enumeration {
	if p.info == nil {
		return nil
	}
	return p.info.Enum
}

// IsNull indicates if the parameter is absent.
func (p Param) IsNull() bool { return p.Value.IsNull() }

// IsNumber determines if the parameter stores the integer value type.
func (p Param) IsNumber() bool { return p.Type().IsNumber() }

// Params is the sequence of event parameters. The sequence is
// indexed by the position of the parameter in the event schema,
// that is, `table[type].Params`, and it always has as many slots as
// there are parameters in the schema. The parameters that were not
// populated have the null value. Parameters that are not described by
// the schema are appended after the schema slots.
//
// The getter methods accept either the parameter index or the parameter
// name (methods with the ByName suffix). Getters don't return errors. If the
// parameter is not found, or it holds the value of a different kind, the zero
// value of the requested type is returned.
type Params []Param

// NewParams creates the parameters for the specified event type, with the slots
// allocated according to the schema in the event table.
func NewParams(typ Type) Params {
	if int(typ) >= len(table) {
		return nil
	}
	schema := table[typ].Params
	if len(schema) == 0 {
		return nil
	}
	pars := make(Params, len(schema))
	for i := range schema {
		pars[i].info = &schema[i]
	}
	return pars
}

// NewParam creates a standalone parameter with its own descriptor, which is not part of the
// event schema. It is useful to build parameters for events that are not tied to the table
// schema, such as synthetic events or the test fixtures.
func NewParam(name string, typ params.Type, v params.Value, opts ...params.ParamOption) Param {
	var o params.ParamOpts
	for _, opt := range opts {
		opt(&o)
	}
	return Param{Value: v, info: &params.ParamInfo{Name: name, Type: typ, Flags: o.Flags, Enum: o.Enum}}
}

// ParamsOf creates the parameters from the given standalone parameters.
func ParamsOf(pars ...Param) Params { return Params(pars) }

// Size returns the number of parameter slots, including the absent parameters.
func (pars Params) Size() int { return len(pars) }

// Len returns the number of parameters that are present.
func (pars Params) Len() int {
	var n int
	for i := range pars {
		if !pars[i].Value.IsNull() {
			n++
		}
	}
	return n
}

// Index returns the index of the parameter slot with the given name or -1
// if there is no such slot. The slot may be vacant, so use Has or Contains to
// determine if the parameter has a value. A linear scan is faster than the map
// lookup for the handful of parameters that events carry.
func (pars Params) Index(name string) int {
	for i := range pars {
		if info := pars[i].info; info != nil && info.Name == name {
			return i
		}
	}
	return -1
}

// Has determines if the parameter at the given index is present.
func (pars Params) Has(idx int) bool {
	return idx >= 0 && idx < len(pars) && !pars[idx].Value.IsNull()
}

// Contains determines whether the parameter with the specified name is present.
func (pars Params) Contains(name string) bool { return pars.Has(pars.Index(name)) }

// Get returns the parameter at the given index. The null parameter is returned if the index is out of bounds.
func (pars Params) Get(idx int) Param {
	if idx < 0 || idx >= len(pars) {
		return Param{}
	}
	return pars[idx]
}

// GetByName returns the parameter with the specified name. The null parameter is returned if not found.
func (pars Params) GetByName(name string) Param { return pars.Get(pars.Index(name)) }

// Name returns the name of the parameter at the given index.
func (pars Params) Name(idx int) string { return pars.Get(idx).Name() }

// Type returns the logical type of the parameter at the given index.
func (pars Params) Type(idx int) params.Type { return pars.Get(idx).Type() }

// Value returns the value of the parameter at the given index.
func (pars Params) Value(idx int) params.Value { return pars.Get(idx).Value }

// ValueByName returns the value of the parameter with the given name.
func (pars Params) ValueByName(name string) params.Value { return pars.GetByName(name).Value }

// Format returns the string representation of the parameter at the given index. The
// parameter value is resolved according to the parameter type. For instance, if the type
// is `Status`, the system error code is converted to the error message.
func (pars Params) Format(idx int) string {
	if idx < 0 || idx >= len(pars) {
		return ""
	}
	return pars[idx].String()
}

// FormatByName returns the string representation of the parameter with the given name.
func (pars Params) FormatByName(name string) string { return pars.Format(pars.Index(name)) }

// Set assigns the value to the parameter at the given index. Out-of-bounds indices are ignored.
func (pars Params) Set(idx int, v params.Value) {
	if idx >= 0 && idx < len(pars) {
		pars[idx].Value = v
	}
}

// SetByName assigns the value to the parameter with the given name. If the event schema doesn't
// declare the parameter, a new parameter is appended, and its type is inferred from the value kind.
func (pars *Params) SetByName(name string, v params.Value) {
	if i := pars.Index(name); i >= 0 {
		(*pars)[i].Value = v
		return
	}
	*pars = append(*pars, Param{Value: v, info: &params.ParamInfo{Name: name, Type: v.ParamType()}})
}

// Append sets the parameter value and overrides the type described in the schema. Prefer SetByName
// when the schema already declares the correct type. This method is useful for parameters that
// are not part of the schema, or when the type has to be changed on the event instance.
func (pars *Params) Append(name string, typ params.Type, v params.Value, opts ...params.ParamOption) {
	var o params.ParamOpts
	for _, opt := range opts {
		opt(&o)
	}
	if i := pars.Index(name); i >= 0 {
		cur := (*pars)[i].info
		if cur.Type != typ || (o.Enum != nil && cur.Enum == nil) || (o.Flags != nil && cur.Flags == nil) {
			info := *cur
			info.Type = typ
			if o.Enum != nil {
				info.Enum = o.Enum
			}
			if o.Flags != nil {
				info.Flags = o.Flags
			}
			(*pars)[i].info = &info
		}
		(*pars)[i].Value = v
		return
	}
	*pars = append(*pars, Param{Value: v, info: &params.ParamInfo{Name: name, Type: typ, Flags: o.Flags, Enum: o.Enum}})
}

// Remove clears the parameter with the given name.
func (pars Params) Remove(name string) {
	if i := pars.Index(name); i >= 0 {
		pars[i].Value = params.Value{}
	}
}

// Rename changes the name of the present parameter. The event schema in the table
// is not affected, since the new descriptor is created for the renamed parameter.
// It returns false if the parameter is not found.
func (pars Params) Rename(old, new string) bool {
	i := pars.Index(old)
	if !pars.Has(i) {
		return false
	}
	info := *pars[i].info
	info.Name = new
	if old == new {
		return true
	}
	if j := pars.Index(new); j >= 0 {
		// reuse the slot with the colliding name
		pars[j].Value = pars[i].Value
		pars[j].info = &info
		pars[i].Value = params.Value{}
		return true
	}
	pars[i].info = &info
	return true
}

// Present returns the parameters that have a value.
func (pars Params) Present() []Param {
	s := make([]Param, 0, len(pars))
	for i := range pars {
		if !pars[i].Value.IsNull() {
			s = append(s, pars[i])
		}
	}
	return s
}

// GetUint8 returns the uint8 value of the parameter at the given index.
func (pars Params) GetUint8(idx int) uint8 { return pars.Value(idx).Uint8() }

// GetUint16 returns the uint16 value of the parameter at the given index.
func (pars Params) GetUint16(idx int) uint16 { return pars.Value(idx).Uint16() }

// GetUint32 returns the uint32 value of the parameter at the given index.
func (pars Params) GetUint32(idx int) uint32 { return pars.Value(idx).Uint32() }

// GetUint64 returns the uint64 value of the parameter at the given index.
func (pars Params) GetUint64(idx int) uint64 { return pars.Value(idx).Uint64() }

// GetInt8 returns the int8 value of the parameter at the given index.
func (pars Params) GetInt8(idx int) int8 { return pars.Value(idx).Int8() }

// GetInt16 returns the int16 value of the parameter at the given index.
func (pars Params) GetInt16(idx int) int16 { return pars.Value(idx).Int16() }

// GetInt32 returns the int32 value of the parameter at the given index.
func (pars Params) GetInt32(idx int) int32 { return pars.Value(idx).Int32() }

// GetInt64 returns the int64 value of the parameter at the given index.
func (pars Params) GetInt64(idx int) int64 { return pars.Value(idx).Int64() }

// GetBool returns the boolean value of the parameter at the given index.
func (pars Params) GetBool(idx int) bool { return pars.Value(idx).Bool() }

// GetFloat32 returns the float32 value of the parameter at the given index.
func (pars Params) GetFloat32(idx int) float32 { return pars.Value(idx).Float32() }

// GetFloat64 returns the float64 value of the parameter at the given index.
func (pars Params) GetFloat64(idx int) float64 { return pars.Value(idx).Float64() }

// GetString returns the raw string value of the parameter at the given index.
// Use Format to obtain the string representation of the parameter value of any type.
func (pars Params) GetString(idx int) string { return pars.Value(idx).Str() }

// GetBytes returns the binary value of the parameter at the given index.
func (pars Params) GetBytes(idx int) []byte { return pars.Value(idx).Bytes() }

// GetIP returns the IP address of the parameter at the given index.
func (pars Params) GetIP(idx int) net.IP { return pars.Value(idx).IP() }

// GetTime returns the timestamp of the parameter at the given index.
// The Unix epoch is returned if the parameter is not found.
func (pars Params) GetTime(idx int) time.Time { return pars.Value(idx).Time() }

// GetAddress returns the memory address of the parameter at the given index.
func (pars Params) GetAddress(idx int) va.Address { return va.Address(pars.Value(idx).Uint64()) }

// GetUint64Slice returns the slice of integers of the parameter at the given index.
func (pars Params) GetUint64Slice(idx int) []uint64 { return pars.Value(idx).U64Slice() }

// GetStringSlice returns the slice of strings of the parameter at the given index.
func (pars Params) GetStringSlice(idx int) []string { return pars.Value(idx).StrSlice() }

// GetAddresses returns the slice of addresses, such as the call stack
// return addresses, of the parameter at the given index.
func (pars Params) GetAddresses(idx int) []va.Address { return addresses(pars.Value(idx).U64Slice()) }

// GetUint8ByName returns the uint8 value of the parameter with the given name.
func (pars Params) GetUint8ByName(name string) uint8 { return pars.ValueByName(name).Uint8() }

// GetUint16ByName returns the uint16 value of the parameter with the given name.
func (pars Params) GetUint16ByName(name string) uint16 { return pars.ValueByName(name).Uint16() }

// GetUint32ByName returns the uint32 value of the parameter with the given name.
func (pars Params) GetUint32ByName(name string) uint32 { return pars.ValueByName(name).Uint32() }

// GetUint64ByName returns the uint64 value of the parameter with the given name.
func (pars Params) GetUint64ByName(name string) uint64 { return pars.ValueByName(name).Uint64() }

// GetInt8ByName returns the int8 value of the parameter with the given name.
func (pars Params) GetInt8ByName(name string) int8 { return pars.ValueByName(name).Int8() }

// GetInt16ByName returns the int16 value of the parameter with the given name.
func (pars Params) GetInt16ByName(name string) int16 { return pars.ValueByName(name).Int16() }

// GetInt32ByName returns the int32 value of the parameter with the given name.
func (pars Params) GetInt32ByName(name string) int32 { return pars.ValueByName(name).Int32() }

// GetInt64ByName returns the int64 value of the parameter with the given name.
func (pars Params) GetInt64ByName(name string) int64 { return pars.ValueByName(name).Int64() }

// GetBoolByName returns the boolean value of the parameter with the given name.
func (pars Params) GetBoolByName(name string) bool { return pars.ValueByName(name).Bool() }

// GetFloat32ByName returns the float32 value of the parameter with the given name.
func (pars Params) GetFloat32ByName(name string) float32 { return pars.ValueByName(name).Float32() }

// GetFloat64ByName returns the float64 value of the parameter with the given name.
func (pars Params) GetFloat64ByName(name string) float64 { return pars.ValueByName(name).Float64() }

// GetStringByName returns the raw string value of the parameter with the given name.
func (pars Params) GetStringByName(name string) string { return pars.ValueByName(name).Str() }

// GetBytesByName returns the binary value of the parameter with the given name.
func (pars Params) GetBytesByName(name string) []byte { return pars.ValueByName(name).Bytes() }

// GetIPByName returns the IP address of the parameter with the given name.
func (pars Params) GetIPByName(name string) net.IP { return pars.ValueByName(name).IP() }

// GetTimeByName returns the timestamp of the parameter with the given name.
func (pars Params) GetTimeByName(name string) time.Time { return pars.ValueByName(name).Time() }

// GetAddressByName returns the memory address of the parameter with the given name.
func (pars Params) GetAddressByName(name string) va.Address {
	return va.Address(pars.ValueByName(name).Uint64())
}

// GetUint64SliceByName returns the slice of integers of the parameter with the given name.
func (pars Params) GetUint64SliceByName(name string) []uint64 {
	return pars.ValueByName(name).U64Slice()
}

// GetStringSliceByName returns the slice of strings of the parameter with the given name.
func (pars Params) GetStringSliceByName(name string) []string {
	return pars.ValueByName(name).StrSlice()
}

// GetAddressesByName returns the slice of addresses of the parameter with the given name.
func (pars Params) GetAddressesByName(name string) []va.Address {
	return addresses(pars.ValueByName(name).U64Slice())
}

func addresses(s []uint64) []va.Address {
	if s == nil {
		return nil
	}
	return unsafe.Slice((*va.Address)(unsafe.Pointer(unsafe.SliceData(s))), len(s))
}

// sortedPresent appends to buf the indices of present parameters sorted
// by the parameter name. The insertion sort is optimal for a few elements
// and doesn't allocate if the buffer has enough capacity.
func (pars Params) sortedPresent(buf []int) []int {
	for i := range pars {
		if !pars[i].Value.IsNull() {
			buf = append(buf, i)
		}
	}
	for i := 1; i < len(buf); i++ {
		for j := i; j > 0 && pars[buf[j]].Name() < pars[buf[j-1]].Name(); j-- {
			buf[j], buf[j-1] = buf[j-1], buf[j]
		}
	}
	return buf
}

// DisplayName renders the parameter name according to the currently active parameter case style.
func (p *Param) DisplayName() string {
	name := p.Name()
	switch ParamNameCaseStyle {
	case DotCase:
		return strings.ReplaceAll(name, "_", ".")
	case PascalCase:
		return strings.ReplaceAll(caser.String(strings.ReplaceAll(name, "_", " ")), " ", "")
	case CamelCase:
		s := strings.ReplaceAll(caser.String(strings.ReplaceAll(name, "_", " ")), " ", "")
		if s == "" {
			return s
		}
		return strings.ToLower(s[:1]) + s[1:]
	default:
		return name
	}
}

// String returns the string representation of the event parameters. Parameter names are rendered according
// to the currently active parameter style case.
func (pars Params) String() string {
	var sb strings.Builder
	var buf [32]int
	idx := pars.sortedPresent(buf[:0])
	for i, n := range idx {
		par := pars[n]
		sb.WriteString(par.DisplayName())
		sb.WriteString(ParamKVDelimiter)
		sb.WriteString(par.String())
		if i != len(idx)-1 {
			sb.WriteString(", ")
		}
	}
	return sb.String()
}

// Colorize renders the full parameter list for the {{.Params}} tag.
// Each entry is formatted as: key <separator> value, with the key in
// amber, the separator dim, and the value semantically coloured.
func (pars Params) Colorize() string {
	var buf [32]int
	idx := pars.sortedPresent(buf[:0])
	if len(idx) == 0 {
		return ""
	}

	var b strings.Builder
	b.Grow(len(idx) * 40)

	for i, n := range idx {
		p := pars[n]
		if i > 0 {
			b.WriteString(colorizer.SpanDim(", "))
		}
		b.WriteString(colorizer.Span(colorizer.Amber, p.Name()))
		b.WriteString(colorizer.SpanDim(ParamKVDelimiter))
		b.WriteString(p.color())
	}

	return b.String()
}
