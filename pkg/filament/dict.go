//go:build filament && windows
// +build filament,windows

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

package filament

import (
	"errors"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filament/cpython"
)

var (
	seq        = cpython.PyUnicodeFromString("seq")
	pid        = cpython.PyUnicodeFromString("pid")
	ppid       = cpython.PyUnicodeFromString("ppid")
	cwd        = cpython.PyUnicodeFromString("cwd")
	exec       = cpython.PyUnicodeFromString("exe")
	comm       = cpython.PyUnicodeFromString("comm")
	sid        = cpython.PyUnicodeFromString("sid")
	tid        = cpython.PyUnicodeFromString("tid")
	cpu        = cpython.PyUnicodeFromString("cpu")
	name       = cpython.PyUnicodeFromString("name")
	cat        = cpython.PyUnicodeFromString("category")
	desc       = cpython.PyUnicodeFromString("description")
	host       = cpython.PyUnicodeFromString("host")
	ts         = cpython.PyUnicodeFromString("timestamp")
	parameters = cpython.PyUnicodeFromString("params")

	errDictAllocate = errors.New("couldn't allocate a new dict")
)

// newEventDict constructs a Python dictionary object from event structure. This dictionary object is
// passed to the event dispatching function in the filament.
func newEventDict(evt *event.Event) (*cpython.Dict, error) {
	dict := cpython.NewDict()
	if dict.IsNull() {
		return nil, errDictAllocate
	}

	// insert canonical event fields
	dict.Insert(seq, cpython.NewPyObjectFromValue(evt.Seq))
	dict.Insert(pid, cpython.NewPyObjectFromValue(evt.PID))
	dict.Insert(tid, cpython.NewPyObjectFromValue(evt.Tid))
	dict.Insert(cpu, cpython.NewPyObjectFromValue(evt.CPU))
	dict.Insert(name, cpython.NewPyObjectFromValue(evt.Name))
	dict.Insert(cat, cpython.NewPyObjectFromValue(string(evt.Category)))
	dict.Insert(desc, cpython.NewPyObjectFromValue(evt.Description))
	dict.Insert(host, cpython.NewPyObjectFromValue(evt.Host))
	dict.Insert(ts, cpython.NewPyObjectFromValue(evt.Timestamp))

	// insert process state fields
	ps := evt.PS
	if ps != nil {
		dict.Insert(ppid, cpython.NewPyObjectFromValue(ps.Ppid))
		dict.Insert(cwd, cpython.NewPyObjectFromValue(ps.Cwd))
		dict.Insert(exec, cpython.NewPyObjectFromValue(ps.Name))
		dict.Insert(comm, cpython.NewPyObjectFromValue(ps.Cmdline))
		dict.Insert(sid, cpython.NewPyObjectFromValue(ps.SID))
	}

	// insert event parameters
	pars := cpython.NewDict()
	for _, par := range evt.Params {
		var val interface{}
		var err error
		switch par.Type {
		case params.Uint8:
			val, err = evt.Params.GetUint8(par.Name)
		case params.Uint16, params.Port:
			val, err = evt.Params.GetUint16(par.Name)
		case params.Uint32, params.PID, params.TID:
			val, err = evt.Params.GetUint32(par.Name)
		case params.Uint64:
			val, err = evt.Params.GetUint64(par.Name)
		case params.Time:
			val, err = evt.Params.GetTime(par.Name)
		case params.IP:
			val, err = evt.Params.GetIP(par.Name)
		default:
			val = evt.GetParamAsString(par.Name)
		}
		if err != nil {
			continue
		}
		param := cpython.NewPyObjectFromValue(val)
		if param.IsNull() {
			continue
		}
		pars.Insert(cpython.PyUnicodeFromString(par.Name), param)
	}

	dict.Insert(parameters, pars.Object())

	return dict, nil
}
