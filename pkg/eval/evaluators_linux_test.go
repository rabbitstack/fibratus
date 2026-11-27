/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package eval

import (
	"reflect"
	"slices"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

func TestLinuxEvaluatorsInvariants(t *testing.T) {
	var flds []Field
	for _, src := range []fields.Source{fields.SourceProcess, fields.SourceFile, fields.SourceNetwork, fields.SourceMemory, fields.SourceThread, fields.SourceEvent} {
		flds = append(flds, evaluatedFields(src)...)
	}
	// the environment has one variable, since the order of the variables is not defined.
	// ps.envs is read with and without the name of the variable
	for _, arg := range []string{"PATH", "PA", "HOME", "nope"} {
		flds = append(flds, NewField(fields.PsEnvs, string(fields.PsEnvs), arg))
	}
	flds = slices.DeleteFunc(flds, func(f Field) bool { return f.Name == fields.EvtArg })

	str := func(name, v string) event.Param { return event.NewParam(name, params.String, params.Str(v)) }
	i64 := func(name string, v int64) event.Param { return event.NewParam(name, params.Int64, params.I64(v)) }
	u64 := func(name string, v uint64) event.Param { return event.NewParam(name, params.Uint64, params.U64(v)) }
	u32 := func(name string, v uint32) event.Param { return event.NewParam(name, params.Uint32, params.U32(v)) }
	u16 := func(name string, v uint16) event.Param { return event.NewParam(name, params.Uint16, params.U16(v)) }

	parent := &pstypes.PS{PID: 1, Name: "init", Cmdline: "/sbin/init", Exe: "/sbin/init", Cwd: "/", Username: "root",
		Args: []string{"--system"}, Envs: map[string]string{"HOME": "/root"}}
	proc := &pstypes.PS{PID: 1023, Ppid: 1, Name: "bash", Cmdline: "bash -c id", Exe: "/bin/bash", Cwd: "/tmp", Username: "nedo",
		UID: 1000, GID: 100, Args: []string{"-c", "id"}, Envs: map[string]string{"PATH": "/usr/bin"}, Parent: parent}

	all := []event.Param{
		str(params.FilePath, "/tmp/payload.so"), str(params.FileNewPath, "/tmp/renamed.txt"),
		i64(params.DirFD, -100), i64(params.FD, 3), u64(params.FileFlags, 0x241), u64(params.FileMode, 0o644),
		i64(params.Retval, -13), u32(params.SyscallID, 59), i64(params.TargetProcessID, -1),
		i64(params.PtraceRequest, 16), i64(params.PrctlOption, 15), u64(params.CloneFlags, 0x11),
		u16(params.NetDport, 443), u16(params.NetSport, 50000), u16(params.SockFamily, 2), str(params.SockPath, "/tmp/app.sock"),
		u64(params.MemBaseAddress, 0x7f0000), u64(params.MemRegionSize, 4096), u32(params.MemProtect, 7),
		u64(params.MmapFlags, 1), u64(params.MmapOffset, 8),
	}
	mk := func(typ event.Type, ps *pstypes.PS, p ...event.Param) *event.Event {
		return &event.Event{Type: typ, PID: 1023, Tid: 2048, PS: ps, Params: event.ParamsOf(p...)}
	}
	evts := map[string]*event.Event{
		"empty":          {},
		"ps, no params":  mk(event.Execve, proc),
		"no ps, params":  mk(event.Openat, nil, all...),
		"ps and params":  mk(event.Openat, proc, all...),
		"orphan":         mk(event.Openat, &pstypes.PS{PID: 1023, Name: "x"}, all...),
		"clone thread":   mk(event.Clone, proc, u64(params.CloneFlags, 0x10000)),
		"connect":        mk(event.Connect, proc, all...),
		"mmap":           mk(event.Mmap, proc, all...),
		"uid from param": mk(event.Openat, nil, u32(params.UID, 42), u32(params.GID, 43)),
		"no envs":        mk(event.Openat, &pstypes.PS{PID: 2}),
	}

	x := newExtractor(flds, nil, nil)
	for _, f := range x.fields {
		if f.eval == nil {
			t.Fatalf("%s has no evaluator", f.String())
		}
	}
	assertEvaluatorInvariants(t, x, flds, evts)
}

func TestLinuxFieldValues(t *testing.T) {
	str := func(name, v string) event.Param { return event.NewParam(name, params.String, params.Str(v)) }
	i64 := func(name string, v int64) event.Param { return event.NewParam(name, params.Int64, params.I64(v)) }
	u64 := func(name string, v uint64) event.Param { return event.NewParam(name, params.Uint64, params.U64(v)) }
	parent := &pstypes.PS{PID: 1, Name: "init", Envs: map[string]string{"HOME": "/root"}}
	proc := &pstypes.PS{PID: 1023, Ppid: 1, Name: "bash", Exe: "/bin/bash", UID: 1000, GID: 100,
		Envs: map[string]string{"PATH": "/usr/bin"}, Parent: parent}
	evt := &event.Event{Type: event.Openat, PID: 1023, Tid: 2048, PS: proc, Params: event.ParamsOf(
		str(params.FilePath, "/tmp/payload.so"), str(params.FileNewPath, "/tmp/renamed.txt"),
		i64(params.DirFD, -100), u64(params.FileFlags, 0x241), i64(params.Retval, -13),
	)}

	tests := []struct {
		field, arg string
		want       any
	}{
		{"ps.pid", "", uint32(1023)},
		{"ps.ppid", "", uint32(1)},
		{"ps.name", "", "bash"},
		{"ps.uid", "", uint32(1000)},
		{"ps.gid", "", uint32(100)},
		{"ps.parent.name", "", "init"},
		{"ps.parent.pid", "", uint32(1)},
		{"ps.envs", "PATH", "/usr/bin"},
		{"ps.envs", "PA", "/usr/bin"},
		{"ps.envs", "NOPE", ""},
		{"ps.envs", "", []string{"PATH:/usr/bin"}},
		{"ps.parent.envs", "", []string{"HOME:/root"}},
		{"file.path", "", "/tmp/payload.so"},
		{"file.path.stem", "", "/tmp/payload"},
		{"file.name", "", "payload.so"},
		{"file.extension", "", ".so"},
		{"file.path.target", "", "/tmp/renamed.txt"},
		{"file.dirfd", "", int64(-100)},
		{"file.flags", "", uint64(0x241)},
		{"file.fd", "", int64(0)},
		{"evt.retval", "", int64(-13)},
		{"thread.tid", "", uint32(2048)},
		{"thread.pid", "", uint32(1023)},
	}
	for _, tt := range tests {
		name := tt.field
		if tt.arg != "" {
			name += "[" + tt.arg + "]"
		}
		t.Run(name, func(t *testing.T) {
			f := NewField(fields.Field(tt.field), name, tt.arg)
			ev, err := GetEvaluator(f)
			if err != nil {
				t.Fatal(err)
			}
			got := ev.Eval(&EvalCtx{Evt: evt})
			if got == nil {
				t.Fatalf("%s has no value", name)
			}
			assertEqualValue(t, tt.want, got)
		})
	}
}

func assertEqualValue(t *testing.T, want, got any) {
	t.Helper()
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("want %#v (%T), got %#v (%T)", want, want, got, got)
	}
}
