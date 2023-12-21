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
	// CIDRContainsFn identifies the CIDR_CONTAINS function
	CIDRContainsFn Fn = iota + 1
	// MD5Fn represents the MD5 function
	MD5Fn
	// ConcatFn represents the CONCAT function
	ConcatFn
	// LtrimFn represents the LTRIM function
	LtrimFn
	// RtrimFn represents the RTRIM function
	RtrimFn
	// LowerFn represents the LOWER function
	LowerFn
	// UpperFn represents the UPPER function
	UpperFn
	// ReplaceFn represents the REPLACE function
	ReplaceFn
	// SplitFn represents the SPLIT function
	SplitFn
	// LengthFn represents the LENGTH function
	LengthFn
	// IndexOfFn represents the INDEXOF function
	IndexOfFn
	// SubstrFn represents the SUBSTR function
	SubstrFn
	// EntropyFn represents the ENTROPY function
	EntropyFn
	// RegexFn represents the REGEX function
	RegexFn
	// IsMinidumpFn represents the ISMINIDUMP function
	IsMinidumpFn
	// BaseFn represents the BASE function
	BaseFn
	// DirFn represents the DIR function
	DirFn
	// SymlinkFn represents the SYMLINK function
	SymlinkFn
	// ExtFn represents the EXT function
	ExtFn
	// GlobFn represents the GLOB function
	GlobFn
	// IsAbsFn represents the IS_ABS function
	IsAbsFn
	// VolumeFn represents the VOLUME function
	VolumeFn
	// GetRegValueFn represents the GET_REG_VALUE function
	GetRegValueFn
	// YaraFn represents the YARA function
	YaraFn
)

// ArgType is the type alias for the argument value type.
type ArgType uint8

// ArgsValidation is a function for the custom argument validation logic.
type ArgsValidation func(args []string) error

const (
	// String represents the string argument type.
	String ArgType = iota
	// Number represents the scalar argument type.
	Number
	// IP represents the IP argument type.
	IP
	// Field represents the argument type that is derived
	// from the field literal. Field literal values can
	// be simple primitive types.
	Field
	// Func represents the argument type that is derived
	// from the function return value.
	Func
	// Slice represents the string slice argument type.
	Slice
	// Bool represents the boolean argument type.
	Bool
	// Unknown is the unknown argument type.
	Unknown
)

// String returns the argument type as a string value.
func (typ ArgType) String() string {
	switch typ {
	case String:
		return "string"
	case Number:
		return "number"
	case IP:
		return "ip"
	case Field:
		return "field"
	case Func:
		return "func"
	case Slice:
		return "slice"
	case Bool:
		return "bool"
	}
	return "unknown"
}

// FunctionDesc contains the function signature that
// particular filter function has to satisfy.
type FunctionDesc struct {
	Name               Fn
	Args               []FunctionArgDesc
	ArgsValidationFunc ArgsValidation
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
	case ConcatFn:
		return "CONCAT"
	case LtrimFn:
		return "LTRIM"
	case RtrimFn:
		return "RTRIM"
	case LowerFn:
		return "LOWER"
	case UpperFn:
		return "UPPER"
	case ReplaceFn:
		return "REPLACE"
	case SplitFn:
		return "SPLIT"
	case LengthFn:
		return "LENGTH"
	case IndexOfFn:
		return "INDEXOF"
	case SubstrFn:
		return "SUBSTR"
	case EntropyFn:
		return "ENTROPY"
	case RegexFn:
		return "REGEX"
	case IsMinidumpFn:
		return "IS_MINIDUMP"
	case BaseFn:
		return "BASE"
	case DirFn:
		return "DIR"
	case ExtFn:
		return "EXT"
	case GlobFn:
		return "GLOB"
	case IsAbsFn:
		return "IS_ABS"
	case VolumeFn:
		return "VOLUME"
	case GetRegValueFn:
		return "GET_REG_VALUE"
	case YaraFn:
		return "YARA"
	default:
		return "UNDEFINED"
	}
}

// parseString yields a string value from the specific position in the args slice.
func parseString(index int, args []interface{}) string {
	if index > len(args)-1 {
		return ""
	}
	s, ok := args[index].(string)
	if !ok {
		return ""
	}
	return s
}
