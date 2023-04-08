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

// IsAbs reports whether the path is absolute.
type IsAbs struct{}

func (f IsAbs) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 1 {
		return false, false
	}
	path := parseString(0, args)
	return filepath.IsAbs(path), true
}

func (f IsAbs) Desc() FunctionDesc {
	desc := FunctionDesc{
		Name: IsAbsFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{Field, Func, String}, Required: true},
		},
	}
	return desc
}

func (f IsAbs) Name() Fn { return IsAbsFn }
