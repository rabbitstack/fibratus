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
	"strconv"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/util/colorizer"
)

func normalizeParamValue(_ params.Type, value params.Value) params.Value { return value }

func formatPlatformParam(p Param) (string, bool) {
	if p.Type != params.String {
		return "", false
	}
	value, ok := p.Value.(string)
	if !ok {
		return fmt.Sprintf("%v", p.Value), true
	}
	return value, true
}

func formatPlatformID(value params.Value) string {
	return strconv.FormatUint(value.(uint64), 10)
}

func captureParamType(typ params.Type) params.Type { return typ }

func platformParamColor(p *Param) (string, bool) {
	switch p.Type {
	case params.String:
		return colorizer.Span(colorizer.White, p.String()), true
	case params.Status:
		if p.String() == "0" {
			return colorizer.Span(colorizer.Green, p.String()), true
		}
		return colorizer.Span(colorizer.Red, p.String()), true
	default:
		return "", false
	}
}

// NewParamFromCapture builds a parameter from restored capture state.
func NewParamFromCapture(name string, typ params.Type, value params.Value, _ Type) *Param {
	return &Param{Name: name, Type: typ, Value: value}
}

// GetPid returns the process identifier.
func (pars Params) GetPid() (uint64, error) {
	return pars.getID(params.ProcessID, params.PID)
}

// MustGetPid returns the process identifier or panics.
func (pars Params) MustGetPid() uint64 {
	id, err := pars.GetPid()
	if err != nil {
		panic(err)
	}
	return id
}

// GetPpid returns the parent process identifier.
func (pars Params) GetPpid() (uint64, error) {
	return pars.getID(params.ProcessParentID, params.PID)
}

// MustGetPpid returns the parent process identifier or panics.
func (pars Params) MustGetPpid() uint64 {
	id, err := pars.GetPpid()
	if err != nil {
		panic(err)
	}
	return id
}

// GetTid returns the thread identifier.
func (pars Params) GetTid() (uint64, error) {
	return pars.getID(params.ThreadID, params.TID)
}

// MustGetTid returns the thread identifier or panics.
func (pars Params) MustGetTid() uint64 {
	id, err := pars.GetTid()
	if err != nil {
		panic(err)
	}
	return id
}

func (pars Params) getID(name string, typ params.Type) (uint64, error) {
	param, err := pars.findParam(name)
	if err != nil {
		return 0, err
	}
	if param.Type != typ {
		return 0, fmt.Errorf("%q parameter has unexpected identifier type", name)
	}
	value, ok := param.Value.(uint64)
	if !ok {
		return 0, fmt.Errorf("unable to type cast %q parameter to uint64 identifier", name)
	}
	return value, nil
}
