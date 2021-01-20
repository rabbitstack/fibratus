// +build filament

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
	"github.com/rabbitstack/fibratus/pkg/filament/cpython"
	"github.com/rabbitstack/fibratus/pkg/kevent"
)

var (
	seq      = cpython.PyUnicodeFromString("seq")
	pid      = cpython.PyUnicodeFromString("pid")
	ppid     = cpython.PyUnicodeFromString("ppid")
	cwd      = cpython.PyUnicodeFromString("cwd")
	exec     = cpython.PyUnicodeFromString("exe")
	comm     = cpython.PyUnicodeFromString("comm")
	sid      = cpython.PyUnicodeFromString("sid")
	tid      = cpython.PyUnicodeFromString("tid")
	cpu      = cpython.PyUnicodeFromString("cpu")
	name     = cpython.PyUnicodeFromString("name")
	cat      = cpython.PyUnicodeFromString("category")
	desc     = cpython.PyUnicodeFromString("description")
	host     = cpython.PyUnicodeFromString("host")
	ts       = cpython.PyUnicodeFromString("timestamp")
	kparamsk = cpython.PyUnicodeFromString("kparams")

	errDictAllocate = errors.New("couldn't allocate a new dict")
)

// newKDict constructs a Python dictionary object from the kernel event structure. This dictionary object is
// passed to the event dispatching function in the filament.
func newKDict(kevt *kevent.Kevent) (*cpython.Dict, error) {
	kdict := cpython.NewDict()
	if kdict.IsNull() {
		return nil, errDictAllocate
	}

	// insert canonical kevent fields
	kdict.Insert(seq, cpython.NewPyObjectFromValue(kevt.Seq))
	kdict.Insert(pid, cpython.NewPyObjectFromValue(kevt.PID))
	kdict.Insert(tid, cpython.NewPyObjectFromValue(kevt.Tid))
	kdict.Insert(cpu, cpython.NewPyObjectFromValue(kevt.CPU))
	kdict.Insert(name, cpython.NewPyObjectFromValue(kevt.Name))
	kdict.Insert(cat, cpython.NewPyObjectFromValue(string(kevt.Category)))
	kdict.Insert(desc, cpython.NewPyObjectFromValue(kevt.Description))
	kdict.Insert(host, cpython.NewPyObjectFromValue(kevt.Host))
	kdict.Insert(ts, cpython.NewPyObjectFromValue(kevt.Timestamp))

	// insert process state fields
	ps := kevt.PS
	if ps != nil {
		kdict.Insert(ppid, cpython.NewPyObjectFromValue(ps.Ppid))
		kdict.Insert(cwd, cpython.NewPyObjectFromValue(ps.Cwd))
		kdict.Insert(exec, cpython.NewPyObjectFromValue(ps.Name))
		kdict.Insert(comm, cpython.NewPyObjectFromValue(ps.Comm))
		kdict.Insert(sid, cpython.NewPyObjectFromValue(ps.SID))
	}

	// insert kevent parameters
	kpars := cpython.NewDict()
	for _, kpar := range kevt.Kparams {
		kparam := cpython.NewPyObjectFromValue(kpar.Value)
		if kparam.IsNull() {
			continue
		}
		kpars.Insert(cpython.PyUnicodeFromString(kpar.Name), kparam)
	}

	kdict.Insert(kparamsk, kpars.Object())

	return kdict, nil
}
