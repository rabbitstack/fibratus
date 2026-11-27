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
	"net"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/network"
)

// networkEvaluator returns the net.* evaluator of the field, or nil if the field
// isn't one of them. The net.sip.names and net.dip.names fields resolve the
// addresses with the reverse DNS resolver.
func networkEvaluator(f Field) Evaluator {
	b := evaluatorBase(f)
	switch f.Name {
	case fields.NetSIPNames:
		return ipNames(f, params.NetSIP)
	case fields.NetDIPNames:
		return ipNames(f, params.NetDIP)

	case fields.NetDIP:
		return &IPEvaluator{EvaluatorBase: b, Get: fromParam[net.IP](params.NetDIP, event.Params.GetIPByName)}
	case fields.NetSIP:
		return &IPEvaluator{EvaluatorBase: b, Get: fromParam[net.IP](params.NetSIP, event.Params.GetIPByName)}

	case fields.NetDport:
		return &Uint16Evaluator{EvaluatorBase: b, Get: fromParam(params.NetDport, event.Params.GetUint16ByName)}
	case fields.NetSport:
		return &Uint16Evaluator{EvaluatorBase: b, Get: fromParam(params.NetSport, event.Params.GetUint16ByName)}

	case fields.NetDportName:
		return &StringEvaluator{EvaluatorBase: b, Get: fromParam(params.NetDportName, event.Params.GetStringByName)}
	case fields.NetSportName:
		return &StringEvaluator{EvaluatorBase: b, Get: fromParam(params.NetSportName, event.Params.GetStringByName)}

	case fields.NetL4Proto:
		return stringParam(f, params.NetL4Proto)
	case fields.NetPacketSize:
		return &Uint32Evaluator{EvaluatorBase: b, Get: fromParam(params.NetSize, event.Params.GetUint32ByName)}
	}
	return nil
}

// ipNames reads the names the address in the parameter resolves to.
func ipNames(f Field, param string) Evaluator {
	return &StringSliceEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) ([]string, bool) {
		ip := ctx.Evt.Params.GetIPByName(param)
		res := ctx.Resolvers.ReverseDNS.Of(ctx, network.AddressFromIP(ip))
		if res.Err != nil {
			return nil, false
		}
		return res.Names, true
	}}
}

// memoryEvaluator returns the mem.* evaluator of the field, or nil if the field
// isn't one of them.
func memoryEvaluator(f Field) Evaluator {
	switch f.Name {
	case fields.MemPageType:
		return stringParam(f, params.MemPageType)
	case fields.MemAllocType:
		return stringParam(f, params.MemAllocType)
	case fields.MemProtection:
		return stringParam(f, params.MemProtect)
	case fields.MemBaseAddress:
		return uint64Param(f, params.MemBaseAddress)
	case fields.MemRegionSize:
		return uint64Param(f, params.MemRegionSize)
	case fields.MemProtectionMask:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromParam(params.MemProtectMask, event.Params.GetStringByName)}
	}
	return nil
}

// dnsEvaluator returns the dns.* evaluator of the field, or nil if the field
// isn't one of them.
func dnsEvaluator(f Field) Evaluator {
	b := evaluatorBase(f)
	switch f.Name {
	case fields.DNSName:
		return stringParam(f, params.DNSName)
	case fields.DNSRR:
		return stringParam(f, params.DNSRR)
	case fields.DNSRcode:
		return stringParam(f, params.DNSRcode)
	case fields.DNSOptions:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) []string { return e.GetFlagsAsSlice(params.DNSOpts) })}
	case fields.DNSAnswers:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: fromParam(params.DNSAnswers, event.Params.GetStringSliceByName)}
	}
	return nil
}
