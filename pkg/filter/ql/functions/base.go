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
	"path/filepath"
	"strings"
)

// Base returns the last element of the path.
type Base struct{}

func (f Base) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 1 {
		return false, false
	}
	path, ok := args[0].(string)
	if !ok {
		return false, false
	}
	base := filepath.Base(path)
	if len(args) > 1 {
		ext, ok := args[1].(bool)
		if !ok {
			return base, true
		}
		if !ext {
			n := strings.LastIndex(base, ".")
			if n > 0 {
				return base[:n], true
			}
		}
	}
	return base, true
}

func (f Base) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: BaseFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{Field, Func, String}, Required: true},
			{Keyword: "ext", Types: []ArgType{Bool}, Required: false},
		},
	}
	return desc
}

func (f Base) Name() Fn { return BaseFn }
