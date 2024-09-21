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

package kevent

import "testing"

func TestParamFlags(t *testing.T) {
	var tests = []struct {
		flag     uint64
		flags    ParamFlags
		expected string
	}{
		{0x1fffff, PsAccessRightFlags, "ALL_ACCESS"},
		{0x1400, PsAccessRightFlags, "QUERY_INFORMATION|QUERY_LIMITED_INFORMATION"},
		{0x1800, ThreadAccessRightFlags, "QUERY_LIMITED_INFORMATION"},
		{0x00000002, PsCreationFlags, "WOW64"},
	}

	for i, tt := range tests {
		s := tt.flags.String(tt.flag)
		if s != tt.expected {
			t.Errorf("%d. %q flag mismatch: exp=%s got=%s", i, tt.expected, tt.expected, s)
		}
	}
}
