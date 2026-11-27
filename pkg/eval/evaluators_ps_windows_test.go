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
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/require"
)

func TestProcessEvaluatorsInvariants(t *testing.T) {
	flds := evaluatedFields(fields.SourceProcess)
	// 17 twins and the three fields without one, plus the collections and the access fields
	require.GreaterOrEqual(t, len(flds), 50)
	// the fields with an argument are tried with a few of them. The environment
	// has a single variable, since the order of a map is random
	for _, arg := range []string{"", "winroot", "win", "nope"} {
		flds = append(flds, NewField(fields.PsEnvs, string(fields.PsEnvs), arg))
	}
	for _, arg := range []string{"0", "1", "2", "5", "-2", "x"} {
		flds = append(flds, NewField(fields.PsAncestor, string(fields.PsAncestor), arg))
	}

	full := func(pid uint32, name string) *pstypes.PS {
		return &pstypes.PS{
			PID: pid, Ppid: pid - 1, Name: name, Cmdline: name + " /c whoami", Exe: `C:\Windows\` + name,
			Args: []string{"/c", "whoami"}, Cwd: `C:\Temp`, SID: "S-1-5-32-544", Domain: "NT AUTHORITY",
			Username: "SYSTEM", SessionID: 2, IsWOW64: true, IsPackaged: true, IsProtected: true,
			TokenIntegrityLevel: "HIGH", TokenElevationType: "LIMITED", IsTokenElevated: true,
			Envs:    map[string]string{"winroot": `C:\Windows`},
			Handles: htypes.Handles{{Name: `\BaseNamedObjects\a`, Type: "Mutant"}, {Name: `\Device\b`, Type: "File"}},
			Modules: []pstypes.Module{{Name: `C:\Windows\System32\ntdll.dll`}},
			Mmaps:   []pstypes.Mmap{{}},
		}
	}
	child := full(1023, "cmd.exe")
	child.Parent = full(1022, "explorer.exe")
	child.Parent.Parent = full(1021, "winlogon.exe")
	orphan := full(77, "orphan.exe")
	withPS := func(typ event.Type, ps *pstypes.PS) *event.Event {
		return &event.Event{Type: typ, PID: 1023, Tid: 2048, PS: ps}
	}
	evts := map[string]*event.Event{
		"empty": {},
		"full":  withPS(event.CreateProcess, child),
		"file":  withPS(event.CreateFile, child),
		"open process": {Type: event.OpenProcess, PID: 1023, PS: child, Params: event.ParamsOf(
			event.NewParam(params.DesiredAccess, params.String, params.Str("ALL_ACCESS|TERMINATE")),
			event.NewParam(params.NTStatus, params.String, params.Str("success")))},
		"no parent":      withPS(event.CreateFile, orphan),
		"bare ps":        withPS(event.CreateFile, &pstypes.PS{}),
		"bare parent":    withPS(event.CreateFile, &pstypes.PS{Parent: &pstypes.PS{}}),
		"no ps, process": {Type: event.CreateProcess, PID: 5},
		"no ps, file":    {Type: event.CreateFile, PID: 5},
	}

	x := newExtractor(flds, nil, nil)
	for _, f := range x.fields {
		require.NotNil(t, f.eval, "%s has no evaluator", f.String())
	}
	assertEvaluatorInvariants(t, x, flds, evts)
}
