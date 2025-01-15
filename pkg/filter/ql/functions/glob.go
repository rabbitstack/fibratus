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
)

// Glob returns the names of all files matching the pattern or an empty list if there is no matching file.
type Glob struct{}

func (f Glob) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 1 {
		return false, false
	}
	pattern := parseString(0, args)
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, true
	}
	return matches, true
}

func (f Glob) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: GlobFn,
		Args: []FunctionArgDesc{
			{Keyword: "pattern", Types: []ArgType{Field, BoundField, Func, String}, Required: true},
		},
	}
	return desc
}

func (f Glob) Name() Fn { return GlobFn }
