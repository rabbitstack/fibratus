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
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func moduleEvents() map[string]*event.Event {
	str := func(name, v string) event.Param { return event.NewParam(name, params.String, params.Str(v)) }
	u32 := func(name string, v uint32) event.Param { return event.NewParam(name, params.Uint32, params.U32(v)) }
	u64 := func(name string, v uint64) event.Param { return event.NewParam(name, params.Uint64, params.U64(v)) }
	load := func(typ event.Type, ps ...event.Param) *event.Event {
		return &event.Event{Type: typ, PID: 1023, Params: event.ParamsOf(ps...)}
	}
	full := []event.Param{
		str(params.ModulePath, `C:\Windows\no\such\evil.dll`), str(params.ModuleBase, "7ffe0000"), str(params.ModuleDefaultBase, "10000000"),
		u64(params.ModuleSize, 4096), u32(params.ModuleCheckSum, 7), u32(params.ProcessID, 4096),
		str(params.ModuleSignatureType, "EMBEDDED"), str(params.ModuleSignatureLevel, "AUTHENTICODE"),
		str(params.ModuleCertSubject, "Evil Corp"), str(params.ModuleCertIssuer, "Evil CA"), str(params.ModuleCertSerial, "01"),
	}
	return map[string]*event.Event{
		"empty":          {},
		"load":           load(event.LoadModule, full...),
		"load bare":      load(event.LoadModule),
		"unload":         load(event.UnloadModule, full...),
		"module rundown": load(event.ModuleRundown, full...),
		"no ext":         load(event.LoadModule, str(params.ModulePath, `C:\bin\noext`)),
	}
}

func TestModuleEvaluatorsInvariants(t *testing.T) {
	flds := evaluatedFields(fields.SourceModule)
	require.GreaterOrEqual(t, len(flds), 55)

	x := newExtractor(flds, nil, nil)
	for _, f := range x.fields {
		require.NotNil(t, f.eval, "%s has no evaluator", f.String())
	}
	assertEvaluatorInvariants(t, x, flds, moduleEvents())
}

// TestModuleResolversRunOnlyWhenReached counts the resolver calls: the
// signature is looked up when the expression gets to a signature field, once
// for all the fields that need it, and never if a cheap operand rejects the event.
func TestModuleResolversRunOnlyWhenReached(t *testing.T) {
	var sigCalls, metaCalls int
	r := &Resolvers{
		Signature: NewResolver("signature", func(signature.Key) *signature.Signature { sigCalls++; return nil }),
		FileMeta:  NewResolver("file_metadata", func(string) *fs.FileInfo { metaCalls++; return nil }),
	}
	evt := moduleEvents()["load"]

	run := func(expr string) {
		sigCalls, metaCalls = 0, 0
		p, err := NewProgram("t", expr, WithResolvers(r))
		require.NoError(t, err)
		ctx := AcquireEvalCtx()
		defer ctx.Release()
		p.Eval(evt, ctx)
	}

	run(`module.name = 'other.dll' and module.signature.exists = true`)
	assert.Zero(t, sigCalls, "a cheap operand rejects the event before the signature is looked up")

	run(`module.name = 'evil.dll' and module.signature.exists = true`)
	assert.Equal(t, 1, sigCalls)

	run(`module.name = 'evil.dll' and module.signature.exists = true and module.signature.trusted = true and module.signature.issuer = 'x'`)
	assert.Equal(t, 1, sigCalls, "the fields of the event share one lookup")

	run(`module.name = 'other.dll' and module.is_dll = true`)
	assert.Zero(t, metaCalls)
	run(`module.name = 'evil.dll' and module.is_dll = true and module.is_driver = true`)
	assert.Equal(t, 1, metaCalls)
}
