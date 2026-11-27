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
)

// CIDREvaluator evaluates the cidr_contains function, which tells whether the
// IP address belongs to any of the networks. The networks that are literals are
// parsed once with the function. The ones that aren't, e.g. the result of
// another function, are parsed for every event. The network that can't be parsed
// is skipped.
type CIDREvaluator struct {
	EvaluatorBase
	IP Evaluator
	// Networks are the networks parsed when the function was compiled.
	Networks []*net.IPNet
	// Dynamic are the arguments that have to be evaluated to know the network.
	Dynamic []Evaluator
}

func newCIDREvaluator(args []Evaluator) *CIDREvaluator {
	e := &CIDREvaluator{IP: args[0]}
	for _, arg := range args[1:] {
		cidr, ok := constString(arg)
		if !ok {
			e.Dynamic = append(e.Dynamic, arg)
			continue
		}
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil {
			e.Networks = append(e.Networks, ipnet)
		}
	}
	return e
}

func (e *CIDREvaluator) Eval(ctx *EvalCtx) any {
	var ip net.IP
	switch addr := e.IP.Eval(ctx).(type) {
	case net.IP:
		ip = addr
	case string:
		ip = net.ParseIP(addr)
	}
	for _, ipnet := range e.Networks {
		if ipnet.Contains(ip) {
			return true
		}
	}
	for _, arg := range e.Dynamic {
		cidr, ok := arg.Eval(ctx).(string)
		if !ok {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(cidr); err == nil && ipnet.Contains(ip) {
			return true
		}
	}
	return false
}
