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
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
)

// The functions of the rule language are described here. A description is the
// signature of the function: its name, the arguments, and what the argument can
// be. The parser validates the calls against it. The evaluators of the functions
// that compute the values are in the eval package, which depends on the parser, so
// the signatures can't live next to them.

// Shannon is the entropy algorithm the entropy function accepts.
const Shannon = "shannon"

// indexOrders are the positions the indexof function accepts.
var indexOrders = map[string]bool{"first": true, "any": true, "last": true, "lastany": true}

// catalog holds the signatures of the functions available on the platform.
var catalog = func() map[Fn]FunctionDesc {
	descs := []FunctionDesc{
		baseDesc(),
		cidrContainsDesc(),
		concatDesc(),
		countDesc(),
		dirDesc(),
		entropyDesc(),
		extDesc(),
		foreachDesc(),
		globDesc(),
		indexOfDesc(),
		isAbsDesc(),
		lengthDesc(),
		lowerDesc(),
		ltrimDesc(),
		md5Desc(),
		regexDesc(),
		replaceDesc(),
		rtrimDesc(),
		splitDesc(),
		substrDesc(),
		symlinkDesc(),
		upperDesc(),
		volumeDesc(),
		yaraDesc(),
	}
	descs = append(descs, platformDescs()...)
	m := make(map[Fn]FunctionDesc, len(descs))
	for _, desc := range descs {
		m[desc.Name] = desc
	}
	return m
}()

// Lookup returns the signature of the function by its name, which is case-insensitive.
func Lookup(name string) (FunctionDesc, bool) {
	fn, ok := Parse(name)
	if !ok {
		return FunctionDesc{}, false
	}
	desc, ok := catalog[fn]
	return desc, ok
}

// Names returns the names of the functions available on the platform, sorted.
func Names() []string {
	names := make([]string, 0, len(catalog))
	for fn := range catalog {
		names = append(names, fn.String())
	}
	sort.Strings(names)
	return names
}

// baseDesc returns the signature of the Base function.
func baseDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: BaseFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{Field, BoundField, BoundSegment, BareBoundVariable, Func, String, Slice}, Required: true},
			{Keyword: "ext", Types: []ArgType{Bool}, Required: false},
		},
	}
	return desc
}

// cidrContainsDesc returns the signature of the CIDRContains function.
func cidrContainsDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: CIDRContainsFn,
		Args: []FunctionArgDesc{
			{Keyword: "ip", Types: []ArgType{IP, Field, BoundField, BoundSegment, BareBoundVariable}, Required: true},
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

// concatDesc returns the signature of the Concat function.
func concatDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: ConcatFn,
		Args: []FunctionArgDesc{
			{Keyword: "string1", Types: []ArgType{String, Number, Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
			{Keyword: "string2", Types: []ArgType{String, Number, Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
		},
	}
	offset := len(desc.Args)
	// add optional arguments
	for i := offset; i < maxArgs; i++ {
		desc.Args = append(desc.Args, FunctionArgDesc{Keyword: fmt.Sprintf("string%d", i+1), Types: []ArgType{String, Number, Field, Func}})
	}
	return desc
}

// countDesc returns the signature of the Count function.
func countDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: CountFn,
		Args: []FunctionArgDesc{
			{Keyword: "string|slice", Types: []ArgType{Field, BoundField, BoundSegment, BareBoundVariable, Func, String, Slice}, Required: true},
			{Keyword: "pattern", Types: []ArgType{String}, Required: true},
			{Keyword: "case_insensitive", Types: []ArgType{Bool}, Required: false},
		},
	}
	return desc
}

// dirDesc returns the signature of the Dir function.
func dirDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: DirFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{Field, BoundField, BoundSegment, BareBoundVariable, Func, String, Slice}, Required: true},
		},
	}
	return desc
}

// entropyDesc returns the signature of the Entropy function.
func entropyDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: EntropyFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
			{Keyword: "algo", Types: []ArgType{String}},
		},
		ArgsValidationFunc: func(args []string) error {
			if len(args) == 1 {
				return nil
			}
			if len(args) > 1 && args[1] != Shannon {
				return fmt.Errorf("unsupported entropy algorithm: %s. Available algorithms: %s", args[1],
					strings.Join([]string{Shannon}, "|"))
			}
			return nil
		},
	}
	return desc
}

// extDesc returns the signature of the Ext function.
func extDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: ExtFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{Field, BoundField, Func, BoundSegment, BareBoundVariable, String}, Required: true},
			{Keyword: "dot", Types: []ArgType{Bool}, Required: false},
		},
	}
	return desc
}

// foreachDesc returns the signature of the foreach function.
func foreachDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: ForeachFn,
		Args: []FunctionArgDesc{
			{Keyword: "iterable", Types: []ArgType{Field}, Required: true},
			{Keyword: "var", Types: []ArgType{BareBoundVariable}, Required: true},
			{Keyword: "predicate", Types: []ArgType{Expression}, Required: true},
		},
		ArgsValidationFunc: func(args []string) error {
			s := args[0] // slice/map field name
			v := args[1] // bound variable name
			e := args[2] // expression

			var reserved = map[string]bool{ // reserved bound variable names
				"$ps":       true,
				"$pe":       true,
				"$file":     true,
				"$image":    true,
				"$module":   true,
				"$dll":      true,
				"$thread":   true,
				"$registry": true,
				"$net":      true,
				"$mem":      true,
				"$dns":      true,
				"$evt":      true,
			}

			if reserved[v] {
				return fmt.Errorf("%q is a reserved bound variable name", v)
			}

			var hasBoundVar bool
			var boundSegmentRegexp = regexp.MustCompile(`(\$[a-zA-Z_0-9]+)\.?([a-zA-Z0-9_.$]*)`)

			// scan all bound fields inside expression
			matches := boundSegmentRegexp.FindAllStringSubmatch(e, -1)

			for _, match := range matches {
				// check the bound variable references
				// a valid segment and also verify if
				// the declared bound item is used in
				// the predicate
				switch len(match) {
				case 3:
					if match[2] != "" && !fields.IsSegmentAllowed(fields.Field(s), fields.Segment(match[2])) {
						return fmt.Errorf("unrecognized property %q accessing bound variable %s. Allowed properties [%s]",
							match[2],
							v,
							fields.SegmentsHint(fields.Field(s)))
					}
					if match[1] == v {
						hasBoundVar = true
					}
					if match[1] != v {
						return fmt.Errorf("undeclared bound variable %s in predicate %q", match[1], e)
					}
				default:
					return fmt.Errorf("invalid bound variables in predicate %q", e)
				}
			}

			if !hasBoundVar {
				return fmt.Errorf("unused bound variable %s in predicate %q", v, e)
			}

			var fieldRegexp = regexp.MustCompile(`(ps|pe|file|image|thread|registry|net|mem|handle|dns|evt)\.[a-zA-Z0-9_.$]+`)
			matches = fieldRegexp.FindAllStringSubmatch(e, -1)

			if len(args) > 3 {
				// validate predicate captures. The basic
				// requirements must ensure the field is
				// captured from outer context before it
				// can be used in the predicate
				captures := make(map[string]bool)

				for n := 3; n < len(args); n++ {
					captures[args[n]] = true
				}

				for _, match := range matches {
					if len(match) != 2 {
						continue
					}
					if !captures[match[0]] {
						return fmt.Errorf("field %s used in predicate %q but not captured", match[0], e)
					}
				}

				if len(matches) == 0 && len(captures) > 0 {
					return fmt.Errorf("one of captured field(s) (%s) not used in predicate %q", strings.Join(args[3:], ","), e)
				}
			} else {
				for _, match := range matches {
					if len(match) != 2 {
						continue
					}
					return fmt.Errorf("field %s used in predicate %q but not captured", match[0], e)
				}
			}

			return nil
		},
	}

	offset := len(desc.Args)

	// add optional fields the predicate can capture. Ten fields should be enough for anybody ;)
	for i := offset; i < offset+10; i++ {
		desc.Args = append(desc.Args, FunctionArgDesc{Keyword: "field", Types: []ArgType{Field}})
	}

	return desc
}

// globDesc returns the signature of the Glob function.
func globDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: GlobFn,
		Args: []FunctionArgDesc{
			{Keyword: "pattern", Types: []ArgType{Field, BoundField, Func, BoundSegment, BareBoundVariable, String}, Required: true},
		},
	}
	return desc
}

// indexOfDesc returns the signature of the IndexOf function.
func indexOfDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: IndexOfFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
			{Keyword: "substr", Types: []ArgType{String, Func}, Required: true},
			{Keyword: "index", Types: []ArgType{String}},
		},
		ArgsValidationFunc: func(args []string) error {
			if len(args) == 2 {
				return nil
			}
			if len(args) == 3 && !indexOrders[args[2]] {
				return fmt.Errorf("%s is not a valid index search order. Available options are: first,any,last,lastany", args[2])
			}
			return nil
		},
	}
	return desc
}

// isAbsDesc returns the signature of the IsAbs function.
func isAbsDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: IsAbsFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{Field, BoundField, Func, BoundSegment, BareBoundVariable, String}, Required: true},
		},
	}
	return desc
}

// lengthDesc returns the signature of the Length function.
func lengthDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: LengthFn,
		Args: []FunctionArgDesc{
			{Keyword: "string|slice", Types: []ArgType{Field, BoundField, BoundSegment, BareBoundVariable, Slice, Func}, Required: true},
		},
	}
	return desc
}

// lowerDesc returns the signature of the Lower function.
func lowerDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: LowerFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{String, Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
		},
	}
	return desc
}

// ltrimDesc returns the signature of the Ltrim function.
func ltrimDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: LtrimFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{String, Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
			{Keyword: "prefix", Types: []ArgType{String, Func}, Required: true},
		},
	}
	return desc
}

// md5Desc returns the signature of the MD5 function.
func md5Desc() FunctionDesc {
	return FunctionDesc{
		Name: MD5Fn,
		Args: []FunctionArgDesc{
			{Keyword: "data", Types: []ArgType{Field, String, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
		},
	}
}

// regexDesc returns the signature of the Regex function.
func regexDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: RegexFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{Field, BoundField, String, BoundSegment, BareBoundVariable, Func}, Required: true},
			{Keyword: "regexp", Types: []ArgType{String}, Required: true},
		},
	}
	offset := len(desc.Args)
	// add optional regular expression patterns
	for i := offset; i < maxArgs; i++ {
		desc.Args = append(desc.Args, FunctionArgDesc{Keyword: "regexp", Types: []ArgType{String}})
	}
	return desc
}

// replaceDesc returns the signature of the Replace function.
func replaceDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: ReplaceFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{String, Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
			{Keyword: "old", Types: []ArgType{String, Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
			{Keyword: "new", Types: []ArgType{String, Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
		},
		ArgsValidationFunc: func(args []string) error {
			if len(args) == 3 {
				return nil
			}
			if (len(args)-1)%2 != 0 {
				return errors.New("old/new replacements mismatch")
			}
			return nil
		},
	}
	offset := len(desc.Args)
	// add optional old/new pair arguments
	for i := offset; i < maxArgs; i++ {
		desc.Args = append(desc.Args, FunctionArgDesc{Keyword: fmt.Sprintf("old%d", i+1), Types: []ArgType{String, Field, BoundField, Func}})
		desc.Args = append(desc.Args, FunctionArgDesc{Keyword: fmt.Sprintf("new%d", i+1), Types: []ArgType{String, Field, BoundField, Func}})
	}
	return desc
}

// rtrimDesc returns the signature of the Rtrim function.
func rtrimDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: RtrimFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{String, Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
			{Keyword: "suffix", Types: []ArgType{String, Func}, Required: true},
		},
	}
	return desc
}

// splitDesc returns the signature of the Split function.
func splitDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: SplitFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{String, Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
			{Keyword: "sep", Types: []ArgType{String}, Required: true},
		},
	}
	return desc
}

// substrDesc returns the signature of the Substr function.
func substrDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: SubstrFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{Func, Field, BoundField, BoundSegment, BareBoundVariable}, Required: true},
			{Keyword: "start", Types: []ArgType{Func, Number}, Required: true},
			{Keyword: "end", Types: []ArgType{Func, Number}},
		},
	}
	return desc
}

// symlinkDesc returns the signature of the Symlink function.
func symlinkDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: SymlinkFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{Field, BoundField, BoundSegment, BareBoundVariable, Func, String}, Required: true},
		},
	}
	return desc
}

// upperDesc returns the signature of the Upper function.
func upperDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: UpperFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{String, Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
		},
	}
	return desc
}

// volumeDesc returns the signature of the Volume function.
func volumeDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: VolumeFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{Field, BoundField, BoundSegment, BareBoundVariable, Func, String}, Required: true},
		},
	}
	return desc
}
