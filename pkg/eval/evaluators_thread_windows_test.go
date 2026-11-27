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

	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// threadCallstack is stored the way the probe does: the user frames come
// first, and the last frame is the kernel one.
func threadCallstack() callstack.Callstack {
	return callstack.Callstack{
		{PID: 4096, Addr: 0x140001000, Symbol: "main", Module: `C:\Users\bunny\evil.exe`, ModuleAddress: 0x140000000},
		{PID: 4096, Addr: 0x7ffd0000b000, Symbol: "CreateRemoteThread", Module: `C:\Windows\System32\kernel32.dll`, ModuleAddress: 0x7ffd00000000},
		{PID: 4096, Addr: 0x7ffe0000a000, Symbol: "NtCreateThreadEx", Module: `C:\Windows\System32\ntdll.dll`, ModuleAddress: 0x7ffe00000000},
		{PID: 4096, Addr: 0xfffff80000001000, Symbol: "NtCreateThreadEx", Module: `C:\Windows\system32\ntoskrnl.exe`, ModuleAddress: 0xfffff80000000000},
	}
}

func TestThreadEvaluatorsInvariants(t *testing.T) {
	flds := evaluatedFields(fields.SourceThread)
	require.GreaterOrEqual(t, len(flds), 33)
	// the fields with an argument are tried with a few of them
	for _, f := range []fields.Field{fields.ThreadCallstackModules, fields.ThreadCallstackSymbols} {
		for _, arg := range []string{"0", "2", "3", "4", "9", "x", "-1"} {
			flds = append(flds, NewField(f, string(f), arg))
		}
	}

	str := func(name, v string) event.Param { return event.NewParam(name, params.String, params.Str(v)) }
	u8 := func(name string, v uint8) event.Param { return event.NewParam(name, params.Uint8, params.U8(v)) }
	u32 := func(name string, v uint32) event.Param { return event.NewParam(name, params.Uint32, params.U32(v)) }
	thread := func(typ event.Type, cs callstack.Callstack, ps ...event.Param) *event.Event {
		return &event.Event{Type: typ, PID: 1023, Tid: 2048, Callstack: cs, PS: &pstypes.PS{PID: 1023}, Params: event.ParamsOf(ps...)}
	}
	full := []event.Param{
		u8(params.BasePrio, 8), u8(params.IOPrio, 2), u8(params.PagePrio, 5), u32(params.ProcessID, 4096),
		str(params.KstackBase, "ffff0000"), str(params.KstackLimit, "ffff1000"), str(params.UstackBase, "7ffe0000"),
		str(params.UstackLimit, "7ffe1000"), str(params.StartAddress, "7ffe5000"), str(params.TEB, "7ffd0000"),
		str(params.DesiredAccess, "ALL_ACCESS|TERMINATE"), str(params.NTStatus, "success"),
		str(params.StartAddressSymbol, "RtlUserThreadStart"), str(params.StartAddressModule, "ntdll.dll"),
	}
	evts := map[string]*event.Event{
		"empty":            {},
		"create thread":    thread(event.CreateThread, threadCallstack(), full...),
		"open thread":      thread(event.OpenThread, threadCallstack(), full...),
		"no callstack":     thread(event.CreateThread, nil, full...),
		"single frame":     thread(event.CreateThread, threadCallstack()[:1], full...),
		"no ps, callstack": {Type: event.CreateThread, PID: 1023, Callstack: threadCallstack()},
		"callstack, file":  thread(event.CreateFile, threadCallstack()),
	}

	x := newExtractor(flds, nil, nil)
	for _, f := range x.fields {
		require.NotNil(t, f.eval, "%s has no evaluator", f.String())
	}
	assertEvaluatorInvariants(t, x, flds, evts)
}

func TestFinalUserFrameSignatureIsResolvedOnceWhenReached(t *testing.T) {
	var calls int
	r := &Resolvers{Signature: NewResolver("signature", func(signature.Key) *signature.Signature { calls++; return nil })}
	ps := &pstypes.PS{PID: 1023, Modules: []pstypes.Module{{Name: `C:\Users\bunny\evil.exe`, Size: 0x10000, BaseAddress: 0x140000000}}}
	evt := &event.Event{Type: event.CreateThread, PID: 1023, PS: ps, Callstack: threadCallstack()}

	run := func(expr string) {
		calls = 0
		p, err := NewProgram("t", expr, WithResolvers(r))
		require.NoError(t, err)
		ctx := AcquireEvalCtx()
		defer ctx.Release()
		p.Eval(evt, ctx)
	}

	run(`thread.callstack.final_user_module.name = 'other.exe' and thread.callstack.final_user_module.signature.exists = true`)
	assert.Zero(t, calls, "the cheap operand rejects the event first")
	run(`thread.callstack.final_user_module.name = 'evil.exe' and thread.callstack.final_user_module.signature.exists = true and thread.callstack.final_user_module.signature.trusted = true`)
	assert.Equal(t, 1, calls, "both signature fields share one lookup")
}
