//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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
	"strconv"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// defaultStringType is the type assigned to the string parameters that are not described by the schema.
const defaultStringType = params.String

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
	case params.Flags, params.Flags64:
		flags := p.Flags()
		if flags == nil || v.Kind() != params.KindUint {
			return ""
		}
		return flags.String(v.Uint64())
	default:
		return formatValue(v)
	}
}

// CaptureType returns the type of the parameter saved inside the capture.
func (p Param) CaptureType() params.Type {
	switch p.Type() {
	case params.IP, params.IPv4, params.IPv6:
		if p.Value.IsIPv4() {
			return params.IPv4
		}
		return params.IPv6
	default:
		return p.Type()
	}
}

// setFromCapture sets the parameter restored from the capture state.
func (pars *Params) setFromCapture(name string, typ params.Type, v params.Value) {
	i := pars.Index(name)
	if i < 0 {
		*pars = append(*pars, Param{Value: v, info: &ParamInfo{Name: name, Type: typ}})
		return
	}
	(*pars)[i].Value = v
}

// color applies a semantic colour to a single parameter value based
// on its type and for string types its content.
func (p Param) color() string {
	switch p.Type() {
	case params.String:
		return colorizer.Span(colorizer.White, p.String())
	case params.Status:
		if p.String() == "0" {
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

// GetPid returns the process identifier.
func (pars Params) GetPid() uint32 { return pars.GetUint32ByName(params.ProcessID) }

// GetPpid returns the parent process identifier.
func (pars Params) GetPpid() uint32 { return pars.GetUint32ByName(params.ProcessParentID) }

// GetTid returns the thread identifier.
func (pars Params) GetTid() uint32 { return pars.GetUint32ByName(params.ThreadID) }
