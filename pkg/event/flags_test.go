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

import "testing"

func TestParamFlags(t *testing.T) {
	flags := ParamFlags{
		{Name: "ALL", Value: 0x3},
		{Name: "READ", Value: 0x1},
		{Name: "WRITE", Value: 0x2},
	}
	tests := []struct {
		flag     uint64
		expected string
	}{
		{0x3, "ALL"},
		{0x1, "READ"},
		{0x2, "WRITE"},
		{0, ""},
	}

	for i, tt := range tests {
		s := flags.String(tt.flag)
		if s != tt.expected {
			t.Errorf("%d. %q flag mismatch: exp=%s got=%s", i, tt.expected, tt.expected, s)
		}
	}
}
