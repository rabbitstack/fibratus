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
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// NewParam creates a new event parameter.
func NewParam(name string, typ params.Type, value params.Value, options ...ParamOption) *Param {
	var opts paramOpts
	for _, opt := range options {
		opt(&opts)
	}
	return &Param{Name: name, Type: typ, Value: value, Flags: opts.flags, Enum: opts.enum}
}

func (p *Param) String() string {
	if p.Value == nil {
		return ""
	}
	switch p.Type {
	case params.String, params.Path:
		return p.Value.(string)
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
	case params.Uint32:
		return strconv.FormatUint(uint64(p.Value.(uint32)), 10)
	case params.PID, params.TID:
		return strconv.FormatUint(uint64(p.Value.(uint32)), 10)
	case params.Int32:
		return strconv.Itoa(int(p.Value.(int32)))
	case params.Uint64:
		return strconv.FormatUint(p.Value.(uint64), 10)
	case params.Int64:
		return strconv.FormatInt(p.Value.(int64), 10)
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
		v, ok := p.Value.(uint32)
		if !ok {
			return ""
		}
		return p.Enum[v]
	case params.Flags, params.Flags64:
		if p.Flags == nil {
			return ""
		}
		switch v := p.Value.(type) {
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
	default:
		return fmt.Sprintf("%v", p.Value)
	}
}

func (p Param) CaptureType() params.Type {
	return p.Type
}

// color applies a semantic colour to a single parameter value based
// on its type and for string types its content.
func (p *Param) color() string {
	switch p.Type {
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
		b, ok := p.Value.(bool)
		if !ok {
			return colorizer.Span(colorizer.Coral, p.String())
		}
		if b {
			return colorizer.Span(colorizer.Green, p.String())
		}
		return colorizer.Span(colorizer.Coral, p.String())
	case params.IPv4, params.IPv6:
		return colorizer.Span(colorizer.Blue, p.String())
	case params.Port:
		return colorizer.Span(colorizer.Cyan, p.String())
	case params.PID, params.TID:
		return colorizer.Span(colorizer.Green, p.String())
	default:
		return colorizer.Span(colorizer.White, p.String())
	}
}

// NewParamFromCapture builds a parameter from restored capture state.
func NewParamFromCapture(name string, typ params.Type, value params.Value, _ Type) *Param {
	return &Param{Name: name, Type: typ, Value: value}
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
