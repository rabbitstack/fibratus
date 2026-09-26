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

package filter

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/require"
)

// fuzzExprs mixes extractable shapes with shapes that must fall back to
// default-allow, so the property holds across both paths.
var fuzzExprs = []string{
	"evt.name = 'openat' and file.path startswith '/tmp'",
	"evt.name = 'openat' and file.path = '/etc/passwd'",
	"evt.name = 'openat' and file.path in ('/tmp/a', '/tmp/b') and ps.pid = 42",
	"evt.name in ('openat', 'connect') and ps.pid in (1, 42)",
	"evt.category = 'file' and file.path startswith '/var'",
	"evt.name = 'openat' and file.path matches '/tmp/*'",
	"evt.name = 'openat' and file.path matches ('/tmp/*', '/var/tmp/**')",
	"evt.name = 'openat' and file.path matches '/etc/passwd'",
	"evt.name = 'openat' and file.path matches '/tmp/*/evil'",
	"evt.name = 'openat' and file.path matches '*.so'",
	"evt.name = 'openat' and file.path matches '*'",
	"evt.name = 'openat' and file.path imatches '/TMP/*'",
	"evt.name = 'connect' and net.dport in (80, 443)",
	"evt.name = 'connect' and net.dport = 443 and ps.pid = 42",
	"evt.name = 'kill' and ps.pid = 42",
	"evt.name = 'openat' and file.path != '/tmp/x'",
	"evt.name = 'openat' and not (file.path = '/tmp/x')",
	"evt.name = 'openat' and (ps.pid = 1 or file.path = '/tmp/x')",
	"evt.name = 'openat' and ps.name = 'bash'",
	"file.path startswith '/tmp'",
	"ps.pid = 42",
}

var fuzzTypes = []event.Type{
	event.Openat, event.Connect, event.Kill, event.Execve, event.Mmap, event.Accept,
}

func fuzzEvent(typ event.Type, pid uint64, path string, port uint16) *event.Event {
	evt := &event.Event{
		Type:     typ,
		Category: typ.Category(),
		Name:     typ.String(),
		PID:      pid,
		PS:       &pstypes.PS{PID: pid, Name: "fuzz", Exe: "/bin/fuzz"},
		Params:   event.Params{},
	}
	switch typ {
	case event.Openat, event.Unlink, event.Rename:
		evt.Params[params.FilePath] = &event.Param{Name: params.FilePath, Type: params.Path, Value: path}
	case event.Connect:
		evt.Params[params.NetDport] = &event.Param{Name: params.NetDport, Type: params.Port, Value: port}
	case event.Accept:
		evt.Params[params.NetSport] = &event.Param{Name: params.NetSport, Type: params.Port, Value: port}
	}
	return evt
}

// FuzzApproverNoFalseNegatives is the core soundness property: whatever the
// userspace filter matches, the in-kernel prefilter must also keep.
func FuzzApproverNoFalseNegatives(f *testing.F) {
	f.Add(0, 0, uint64(42), "/tmp/payload", uint16(443))
	f.Add(2, 1, uint64(1), "/var/tmp/x", uint16(80))
	f.Add(5, 3, uint64(0), "/etc/passwd", uint16(22))
	f.Add(8, 2, uint64(4242), "", uint16(0))

	compiled := make([]Filter, len(fuzzExprs))
	plans := make([]*ApproverPlan, len(fuzzExprs))
	for i, expr := range fuzzExprs {
		compiled[i] = mustCompileApprover(f, expr)
		plans[i] = PlanFromFilter(compiled[i])
	}

	f.Fuzz(func(t *testing.T, exprIdx, typeIdx int, pid uint64, path string, port uint16) {
		i := abs(exprIdx) % len(compiled)
		typ := fuzzTypes[abs(typeIdx)%len(fuzzTypes)]

		evt := fuzzEvent(typ, pid, path, port)
		if !compiled[i].Eval(evt) {
			return
		}
		sample := Sample{Type: typ, PID: pid, Port: port}
		if typ == event.Openat || typ == event.Unlink || typ == event.Rename {
			sample.Filename = path
		}
		require.True(t, plans[i].Allows(sample),
			"prefilter dropped a userspace match: expr=%q type=%s pid=%d path=%q port=%d",
			fuzzExprs[i], typ, pid, path, port)
	})
}

func abs(n int) int {
	if n < 0 {
		return -n - 1
	}
	return n
}
