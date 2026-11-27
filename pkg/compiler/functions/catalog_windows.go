/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

// platformDescs returns the signatures of the functions that exist on Windows only.
func platformDescs() []FunctionDesc {
	return []FunctionDesc{getRegValueDesc(), isMinidumpDesc()}
}

// getRegValueDesc returns the signature of the GetRegValue function.
func getRegValueDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: GetRegValueFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{Field, BoundField, String, BoundSegment, BareBoundVariable, Func}, Required: true},
		},
	}
	return desc
}

// isMinidumpDesc returns the signature of the IsMinidump function.
func isMinidumpDesc() FunctionDesc {
	desc := FunctionDesc{
		Name: IsMinidumpFn,
		Args: []FunctionArgDesc{
			{Keyword: "path", Types: []ArgType{String, Field, BoundField, BoundSegment, BareBoundVariable, Func}, Required: true},
		},
	}
	return desc
}
