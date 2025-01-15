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
	"fmt"
	"strconv"
	"strings"
)

// Concat returns a concatenated string of all input arguments.
type Concat struct{}

func (f Concat) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 2 {
		return false, false
	}
	var sb strings.Builder
	for _, arg := range args {
		switch s := arg.(type) {
		case string:
			sb.WriteString(s)
		case int:
			sb.WriteString(strconv.FormatInt(int64(s), 10))
		case uint:
			sb.WriteString(strconv.FormatInt(int64(s), 10))
		case int8:
			sb.WriteString(strconv.FormatInt(int64(s), 10))
		case uint8:
			sb.WriteString(strconv.FormatInt(int64(s), 10))
		case int16:
			sb.WriteString(strconv.FormatInt(int64(s), 10))
		case uint16:
			sb.WriteString(strconv.FormatInt(int64(s), 10))
		case int32:
			sb.WriteString(strconv.FormatInt(int64(s), 10))
		case uint32:
			sb.WriteString(strconv.FormatInt(int64(s), 10))
		case int64:
			sb.WriteString(strconv.FormatInt(s, 10))
		case uint64:
			sb.WriteString(strconv.FormatInt(int64(s), 10))
		}
	}
	return sb.String(), true
}

func (f Concat) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: ConcatFn,
		Args: []FunctionArgDesc{
			{Keyword: "string1", Types: []ArgType{String, Number, Field, BoundField, Func}, Required: true},
			{Keyword: "string2", Types: []ArgType{String, Number, Field, BoundField, Func}, Required: true},
		},
	}
	offset := len(desc.Args)
	// add optional arguments
	for i := offset; i < maxArgs; i++ {
		desc.Args = append(desc.Args, FunctionArgDesc{Keyword: fmt.Sprintf("string%d", i+1), Types: []ArgType{String, Number, Field, Func}})
	}
	return desc
}

func (f Concat) Name() Fn { return ConcatFn }
