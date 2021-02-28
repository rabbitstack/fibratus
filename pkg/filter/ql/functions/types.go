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

const maxArgs = 1 << 5

// Fn is the type alias for function definitions.
type Fn uint16

const (
	// CIDRContains identifies the CIDR_CONTAINS function
	CIDRContainsFn Fn = iota + 1
	// MD5Fn represents the MD5 function
	MD5Fn
)

// ArgType is the type alias for the argument value type.
type ArgType uint8

const (
	// String represents the string argument type.
	String ArgType = iota
	// IP represents the IP argument type.
	IP
	// Field represents the argument type that is derived
	// from the field literal. Field literal values can
	// be simple primitive types.
	Field
	// Unknown is the unknown argument type.
	Unknown
)

// String returns the argument type as a string value.
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
	Name Fn
	Args []FunctionArgDesc
}

// RequiredArgs returns the number of the required function args.
func (f FunctionDesc) RequiredArgs() int {
	var nargs int
	for _, arg := range f.Args {
		if arg.Required {
			nargs++
		}
	}
	return nargs
}

// FunctionArgDesc described each function argument.
type FunctionArgDesc struct {
	Keyword  string
	Required bool
	Types    []ArgType
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
	case MD5Fn:
		return "MD5"
	default:
		return "UNDEFINED"
	}
}
