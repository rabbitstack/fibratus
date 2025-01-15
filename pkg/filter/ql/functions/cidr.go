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

package functions

import (
	"net"
)

// CIDRContains determines if the specified IP is contained within
// the block referenced by the given CIDR mask. The first argument
// in the slice represents the IP address and the rest of the args
// represent IP addresses in CIDR notation.
type CIDRContains struct{}

func (f CIDRContains) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 2 {
		return false, false
	}

	var ip net.IP
	switch addr := args[0].(type) {
	case net.IP:
		ip = addr
	case string:
		ip = net.ParseIP(addr)
	}

	// get CIDR ranges
	cidrs := make([]string, len(args)-1)
	for i, arg := range args[1:] {
		cidr, ok := arg.(string)
		if !ok {
			continue
		}
		cidrs[i] = cidr
	}

	// check each CIDR range
	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipnet.Contains(ip) {
			return true, true
		}
	}

	return false, true
}

func (f CIDRContains) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: CIDRContainsFn,
		Args: []FunctionArgDesc{
			{Keyword: "ip", Types: []ArgType{IP, Field, BoundField}, Required: true},
			{Keyword: "cidr", Types: []ArgType{String}, Required: true},
		},
	}
	offset := len(desc.Args)
	// add optional CIDR arguments
	for i := offset; i < maxArgs; i++ {
		desc.Args = append(desc.Args, FunctionArgDesc{Keyword: "cidr", Types: []ArgType{String, Func}})
	}
	return desc
}

func (f CIDRContains) Name() Fn { return CIDRContainsFn }
