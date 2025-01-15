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
	"strings"
)

// Split produces a slice of substrings separated by the given delimiter.
type Split struct{}

func (f Split) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 2 {
		return false, false
	}
	s := parseString(0, args)
	sep := parseString(1, args)
	return strings.Split(s, sep), true
}

func (f Split) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: SplitFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{String, Field, BoundField, Func}, Required: true},
			{Keyword: "sep", Types: []ArgType{String}, Required: true},
		},
	}
	return desc
}

func (f Split) Name() Fn { return SplitFn }
