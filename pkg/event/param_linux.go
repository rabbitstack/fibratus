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
	"github.com/rabbitstack/fibratus/pkg/util/ntstatus"
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

// String returns the string representation of the parameter value.
func (p Param) String() string {
	if p.Value == nil {
		return ""
	}
	switch p.Type {
	case params.UnicodeString, params.AnsiString, params.Path, params.DOSPath, params.Key, params.HandleType:
		if s, ok := p.Value.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", p.Value)
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
	}
	return fmt.Sprintf("%v", p.Value)
}
