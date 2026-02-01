/*
 * Copyright 2021-present by Nedim Sabic Sabic
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
	"strings"

	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
)

// Count counts the number of items in the slice or substrings
// in the string that is matching a wildcard pattern.
type Count struct{}

func (f Count) Call(args []interface{}) (any, bool) {
	if len(args) < 2 {
		return false, false
	}

	var count int
	var caseInsensitive bool

	pattern := parseString(1, args)

	if len(args) > 2 {
		caseInsensitive, _ = args[2].(bool)
	} else {
		caseInsensitive = true
	}

	switch s := args[0].(type) {
	case string:
		substrings := strings.Fields(s)
		for _, ss := range substrings {
			switch caseInsensitive {
			case true:
				if wildcard.Match(strings.ToLower(pattern), strings.ToLower(ss)) {
					count++
				}
			case false:
				if wildcard.Match(pattern, ss) {
					count++
				}
			}
		}
	case []string:
		for _, i := range s {
			switch caseInsensitive {
			case true:
				if wildcard.Match(strings.ToLower(pattern), strings.ToLower(i)) {
					count++
				}
			case false:
				if wildcard.Match(pattern, i) {
					count++
				}
			}
		}
	}

	return count, true
}

func (f Count) Desc() FunctionDesc {
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

func (f Count) Name() Fn { return CountFn }
