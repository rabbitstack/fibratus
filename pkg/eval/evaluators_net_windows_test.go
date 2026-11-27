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
	"errors"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkMemoryAndDNSEvaluatorsInvariants(t *testing.T) {
	var flds []Field
	for _, src := range []fields.Source{fields.SourceNetwork, fields.SourceMemory, fields.SourceDNS} {
		for _, f := range evaluatedFields(src) {
			// the reverse DNS lookups would leave the machine,
			// they are covered with an injected resolver
			if f.Name != fields.NetSIPNames && f.Name != fields.NetDIPNames {
				flds = append(flds, f)
			}
		}
	}
	require.GreaterOrEqual(t, len(flds), 17)

	str := func(name, v string) event.Param { return event.NewParam(name, params.String, params.Str(v)) }
	u32 := func(name string, v uint32) event.Param { return event.NewParam(name, params.Uint32, params.U32(v)) }
	u64 := func(name string, v uint64) event.Param { return event.NewParam(name, params.Uint64, params.U64(v)) }
	ip := func(name string, a, b, c, d byte) event.Param {
		return event.NewParam(name, params.IPv4, params.IP4(a, b, c, d))
	}
	port := func(name string, v uint16) event.Param { return event.NewParam(name, params.Port, params.U16(v)) }
	with := func(typ event.Type, ps ...event.Param) *event.Event {
		return &event.Event{Type: typ, PID: 1023, Params: event.ParamsOf(ps...)}
	}

	evts := map[string]*event.Event{
		"empty":        {},
		"connect":      with(event.Connect, ip(params.NetSIP, 10, 0, 0, 1), ip(params.NetDIP, 8, 8, 8, 8), port(params.NetSport, 49152), port(params.NetDport, 443), str(params.NetDportName, "https"), str(params.NetSportName, "ephemeral"), str(params.NetL4Proto, "TCP"), u32(params.NetSize, 1500)),
		"connect bare": with(event.Connect),
		"alloc":        with(event.VirtualAlloc, str(params.MemPageType, "PRIVATE"), str(params.MemAllocType, "COMMIT|RESERVE"), str(params.MemProtect, "EXECUTE_READWRITE"), u64(params.MemBaseAddress, 0x7ffe0000), u64(params.MemRegionSize, 4096), str(params.MemProtectMask, "RWX")),
		"alloc bare":   with(event.VirtualAlloc),
		"query dns":    with(event.QueryDNS, str(params.DNSName, "evil.example"), str(params.DNSRR, "A"), str(params.DNSOpts, "QUERY_STANDARD|QUERY_NO_RECURSION")),
		"reply dns":    with(event.ReplyDNS, str(params.DNSName, "evil.example"), str(params.DNSRcode, "NOERROR"), event.NewParam(params.DNSAnswers, params.Slice, params.StrSlice([]string{"1.2.3.4", "5.6.7.8"}))),
		"dns bare":     with(event.ReplyDNS),
	}

	x := newExtractor(flds, nil, nil)
	for _, f := range x.fields {
		require.NotNil(t, f.eval, "%s has no evaluator", f.String())
	}
	assertEvaluatorInvariants(t, x, flds, evts)
}

func TestReverseDNSResolverRunsOnlyWhenReached(t *testing.T) {
	var calls int
	r := &Resolvers{
		ReverseDNS: NewResolver("reverse_dns", func(network.Address) DNSNames {
			calls++
			return DNSNames{Names: []string{"evil.example"}}
		}),
	}
	evt := &event.Event{Type: event.Connect, PID: 1023, Params: event.ParamsOf(
		event.NewParam(params.NetDIP, params.IPv4, params.IP4(8, 8, 8, 8)),
		event.NewParam(params.NetDport, params.Port, params.U16(443)),
	)}

	run := func(expr string) bool {
		calls = 0
		p, err := NewProgram("t", expr, WithResolvers(r))
		require.NoError(t, err)
		ctx := AcquireEvalCtx()
		defer ctx.Release()
		return p.Eval(evt, ctx)
	}

	assert.False(t, run(`net.dport = 80 and net.dip.names in ('evil.example')`))
	assert.Zero(t, calls)
	assert.True(t, run(`net.dport = 443 and net.dip.names in ('evil.example')`))
	assert.Equal(t, 1, calls)

	// a lookup that fails reads as the default value, as an error did
	r.ReverseDNS = NewResolver("reverse_dns", func(network.Address) DNSNames { return DNSNames{Err: errors.New("nxdomain")} })
	assert.False(t, run(`net.dport = 443 and net.dip.names in ('evil.example')`))
}
