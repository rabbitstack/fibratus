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

package event

import "strings"

// ParamFlag defines the mapping between a flag value and its symbolic name.
type ParamFlag struct {
	Name  string
	Value uint64
}

func (f ParamFlag) eval(v uint64) bool {
	return (v == 0 && f.Value == 0) || (f.Value != 0 && (v&f.Value) == f.Value && v != 0)
}

// ParamFlags maps parameter bit flags to symbolic names.
type ParamFlags []ParamFlag

// String returns the names of all flags in the bitmask, separated by pipes.
func (flags ParamFlags) String(value uint64) string {
	var (
		names     strings.Builder
		separator string
	)
	for _, flag := range flags {
		if flag.eval(value) {
			names.WriteString(separator)
			names.WriteString(flag.Name)
			separator = "|"
			value &= ^flag.Value
		}
	}
	return names.String()
}
