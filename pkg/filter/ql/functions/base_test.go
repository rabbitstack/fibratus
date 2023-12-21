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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBase(t *testing.T) {
	var tests = []struct {
		args     []interface{}
		expected interface{}
	}{
		{
			[]interface{}{"C:\\Windows\\cmd.exe"},
			"cmd.exe",
		},
		{
			[]interface{}{"C:\\Windows\\cmd.exe", false},
			"cmd",
		},
		{
			[]interface{}{[]string{"C:\\Windows\\cmd.exe", "C:\\Windows\\notepad.exe"}},
			[]string{"cmd.exe", "notepad.exe"},
		},
		{
			[]interface{}{[]string{"C:\\Windows\\cmd.exe", "C:\\Windows\\notepad.exe"}, false},
			[]string{"cmd", "notepad"},
		},
	}

	for i, tt := range tests {
		f := Base{}
		res, _ := f.Call(tt.args)
		assert.Equal(t, tt.expected, res, fmt.Sprintf("%d. result mismatch: exp=%v got=%v", i, tt.expected, res))
	}
}
