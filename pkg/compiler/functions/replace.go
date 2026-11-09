/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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
	"strings"
)

// Replace replaces occurrences in the string as given by arbitrary old/new replacement pairs.
type Replace struct{}

func (f Replace) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 3 {
		return false, false
	}
	s := parseString(0, args)
	// happy path
	if len(args) == 3 {
		o := parseString(1, args)
		n := parseString(2, args)
		return strings.ReplaceAll(s, o, n), true
	}
	// apply multiple replacements
	repl := s
	for i := 1; i < len(args)-1; i += 2 {
		o, ok := args[i].(string)
		if !ok {
			break
		}
		n, ok := args[i+1].(string)
		if !ok {
			break
		}
		repl = strings.ReplaceAll(repl, o, n)
	}
	return repl, true
}

func (f Replace) Desc() FunctionDesc {
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

func (f Replace) Name() Fn { return ReplaceFn }
