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

// Fn is the type alias for function definitions.
type Fn uint16

const (
	// CIDRContains identifies the CIDR_CONTAINS function
	CIDRContainsFn Fn = iota + 1
)

type ArgType uint8

const (
	String ArgType = iota
	IP
	Field
	Unknown
)

func (typ ArgType) String() string {
	switch typ {
	case String:
		return "string"
	case IP:
		return "ip"
	case Field:
		return "field"
	}
	return "unknown"
}

// FunctionDesc contains the function signature that
// particular filter function has to satisfy.
type FunctionDesc struct {
	Name    Fn
	MinArgs uint8
	Args    []FunctionArgDesc
}

// FunctionArgDesc described each function argument.
type FunctionArgDesc struct {
	Keyword string
	Types   []ArgType
}

// ContainsType returns true if the argument satisfies the given argument type.
func (arg FunctionArgDesc) ContainsType(typ ArgType) bool {
	for _, t := range arg.Types {
		if t == typ {
			return true
		}
	}
	return false
}

// String returns the function name in upper case.
func (f Fn) String() string {
	switch f {
	case CIDRContainsFn:
		return "CIDR_CONTAINS"
	default:
		return "UNDEFINED"
	}
}
