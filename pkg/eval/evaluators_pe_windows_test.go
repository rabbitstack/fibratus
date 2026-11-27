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
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPE(withCert bool) *pe.PE {
	p := &pe.PE{
		NumberOfSections: 5, NumberOfSymbols: 3, ImageBase: "140000000", EntryPoint: "140001000",
		Symbols: []string{"a"}, Imports: []string{"kernel32.dll"}, Imphash: "abcd", IsDotnet: true,
		Anomalies: []string{"wx"}, IsModified: true,
		// a single resource, since the order of a map is random
		VersionResources: map[string]string{pe.Company: "Evil Corp"},
	}
	// verify the signature up front, so the oracle doesn't hit the signature store
	var cert *sys.Cert
	if withCert {
		cert = &sys.Cert{Issuer: "Evil CA", Subject: "Evil Corp", SerialNumber: "01", NotBefore: time.Unix(1, 0), NotAfter: time.Unix(2, 0)}
	}
	p.VerifySignature(func() (bool, bool, *sys.Cert) { return true, withCert, cert })
	return p
}

func TestPEEvaluatorsInvariants(t *testing.T) {
	flds := evaluatedFields(fields.SourcePE)
	require.GreaterOrEqual(t, len(flds), 55)
	for _, f := range []fields.Field{fields.PeResources, fields.PsPeResources} {
		for _, arg := range []string{"", "CompanyName", "Comp", "nope"} {
			flds = append(flds, NewField(f, string(f), arg))
		}
	}

	str := func(name, v string) event.Param { return event.NewParam(name, params.String, params.Str(v)) }
	withPE := func(typ event.Type, p *pe.PE, ps ...event.Param) *event.Event {
		return &event.Event{Type: typ, PID: 1023, PS: &pstypes.PS{PID: 1023, PE: p}, Params: event.ParamsOf(ps...)}
	}
	evts := map[string]*event.Event{
		"empty":        {},
		"pe":           withPE(event.CreateProcess, testPE(true)),
		"pe, no cert":  withPE(event.CreateProcess, testPE(false)),
		"no pe":        {Type: event.CreateProcess, PID: 1023, PS: &pstypes.PS{PID: 1023}},
		"system":       {Type: event.CreateProcess, PID: 4, PS: &pstypes.PS{PID: 4, PE: testPE(true)}},
		"load module":  withPE(event.LoadModule, testPE(true), str(params.ModulePath, `C:\no\such\dll.dll`)),
		"no ps, load":  {Type: event.LoadModule, PID: 1023, Params: event.ParamsOf(str(params.ModulePath, `C:\no\such\dll.dll`))},
		"no ps, other": {Type: event.CreateFile, PID: 1023},
	}

	x := newExtractor(flds, nil, nil)
	for _, f := range x.fields {
		require.NotNil(t, f.eval, "%s has no evaluator", f.String())
	}
	assertEvaluatorInvariants(t, x, flds, evts)
}

// TestPEResolverRunsOnlyWhenReached counts the parses and the signature
// lookups: a cheap operand that rejects the event comes first, and the fields
// that need the PE or the verified signature share one resolver call.
func TestPEResolverRunsOnlyWhenReached(t *testing.T) {
	var parses, lookups int
	r := &Resolvers{
		PE: NewResolver("pe", func(k PEKey) PEResult {
			parses++
			return PEResult{PE: &pe.PE{Imphash: "abcd", VersionResources: map[string]string{pe.Company: "Evil Corp"}}}
		}),
		Signature: NewResolver("signature", func(signature.Key) *signature.Signature { lookups++; return nil }),
	}
	ps := func() *pstypes.PS { return &pstypes.PS{PID: 1023, Name: "evil.exe", Exe: `C:\no\such\evil.exe`} }
	run := func(expr string) bool {
		parses, lookups = 0, 0
		p, err := NewProgram("t", expr, WithResolvers(r))
		require.NoError(t, err)
		ctx := AcquireEvalCtx()
		defer ctx.Release()
		return p.Eval(&event.Event{Type: event.CreateProcess, PID: 1023, PS: ps()}, ctx)
	}

	assert.False(t, run(`ps.name = 'other.exe' and ps.pe.imphash = 'abcd'`))
	assert.Zero(t, parses, "the PE isn't parsed unless the expression gets to the field")

	assert.True(t, run(`ps.name = 'evil.exe' and ps.pe.imphash = 'abcd' and ps.pe.company = 'Evil Corp'`))
	assert.Equal(t, 1, parses, "the fields of the event share one parse")
	assert.Zero(t, lookups)

	run(`ps.name = 'other.exe' and ps.signature.exists = true`)
	assert.Zero(t, parses+lookups)
	run(`ps.name = 'evil.exe' and ps.signature.exists = true and ps.signature.trusted = true`)
	assert.Equal(t, 1, parses)
	assert.Equal(t, 1, lookups, "the signature is verified once")
}
