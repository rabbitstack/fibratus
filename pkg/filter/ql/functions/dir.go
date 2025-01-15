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

import "path/filepath"

// Dir returns all but the last element of the path, typically the path's directory.
type Dir struct{}

func (f Dir) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 1 {
		return false, false
	}
	switch s := args[0].(type) {
	case string:
		return filepath.Dir(s), true
	case []string:
		dirs := make([]string, len(s))
		for i, path := range s {
			dirs[i] = filepath.Dir(path)
		}
		return dirs, true
	}
	return nil, true
}

func (f Dir) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: DirFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{Field, BoundField, Func, String, Slice}, Required: true},
		},
	}
	return desc
}

func (f Dir) Name() Fn { return DirFn }
