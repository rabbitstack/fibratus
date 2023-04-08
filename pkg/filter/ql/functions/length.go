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

// Length returns the number of characters (runes) for string arguments and
// the size of the slice for slice arguments.
type Length struct{}

func (f Length) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 1 {
		return false, false
	}
	switch s := args[0].(type) {
	case string:
		return len([]rune(s)), true
	case []string:
		return len(s), true
	}
	return -1, false
}

func (f Length) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: LengthFn,
		Args: []FunctionArgDesc{
			{Keyword: "string|slice", Types: []ArgType{Field, Slice, Func}, Required: true},
		},
	}
	return desc
}

func (f Length) Name() Fn { return LengthFn }
