/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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
)

// Format applies the template on the provided event.
func (f *Formatter) Format(evt *Event) []byte {
	if evt == nil {
		return []byte{}
	}
	values := map[string]interface{}{
		ts:         evt.Timestamp.String(),
		pid:        strconv.FormatUint(uint64(evt.PID), 10),
		tid:        strconv.FormatUint(uint64(evt.Tid), 10),
		seq:        strconv.FormatUint(evt.Seq, 10),
		cpu:        strconv.FormatUint(uint64(evt.CPU), 10),
		typ:        evt.Name,
		cat:        evt.Category,
		desc:       evt.Description,
		host:       evt.Host,
		meta:       evt.Metadata.String(),
		parameters: evt.Params.String(),
	}

	// add process metadata
	ps := evt.PS
	if ps != nil {
		values[proc] = ps.Name
		values[ppid] = strconv.FormatUint(uint64(ps.Ppid), 10)
		values[cwd] = ps.Cwd
		values[exe] = ps.Exe
		values[cmd] = ps.Cmdline
		values[sid] = ps.SID
		parent := ps.Parent
		if parent != nil {
			values[pproc] = parent.Name
			values[pexe] = parent.Exe
			values[pcmd] = parent.Cmdline
		}
		if ps.PE != nil {
			values[pe] = ps.PE.String()
		}
	}
	// add callstack summary
	if !evt.Callstack.IsEmpty() {
		values[cstack] = evt.Callstack.String()
	}

	if f.expandParamsDot {
		// expand all parameters into the map, so we can ask
		// for specific parameter names in the template
		for _, par := range evt.Params {
			values[".Params."+caser.String(par.Name)] = par.String()
		}
	}

	return f.t.ExecuteString(values)
}
