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

// Substr creates a substring of a given string.
type Substr struct{}

func (f Substr) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 3 {
		return false, false
	}
	s := parseString(0, args)
	start, ok := args[1].(int)
	if !ok {
		return false, false
	}
	end, ok := args[2].(int)
	if !ok {
		return false, false
	}
	if start >= 0 && (end >= start && end < len(s)) {
		return s[start:end], true
	}
	return s, true
}

func (f Substr) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: SubstrFn,
		Args: []FunctionArgDesc{
			{Keyword: "string", Types: []ArgType{Func, Field}, Required: true},
			{Keyword: "start", Types: []ArgType{Func, Number}, Required: true},
			{Keyword: "end", Types: []ArgType{Func, Number}, Required: true},
		},
	}
	return desc
}

func (f Substr) Name() Fn { return SubstrFn }
