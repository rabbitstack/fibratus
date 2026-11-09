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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubstr(t *testing.T) {
	var tests = []struct {
		args     []interface{}
		expected interface{}
	}{
		{
			[]interface{}{"Hello", 0, 4},
			"Hell",
		},
		{
			[]interface{}{"Hello World!", 0, 50},
			"Hello World!",
		},
		{
			[]interface{}{"Hello World!", 4, -1},
			"Hello World!",
		},
		{
			[]interface{}{"Hello World!", -1, 10},
			"Hello World!",
		},
		{
			[]interface{}{"Hello World!", 6, 7},
			"W",
		},
		{
			[]interface{}{"Hello World!", 6},
			"World!",
		},
		{
			[]interface{}{"Hello World!", 20},
			"Hello World!",
		},
	}

	for i, tt := range tests {
		f := Substr{}
		res, _ := f.Call(tt.args)
		assert.Equal(t, tt.expected, res, fmt.Sprintf("%d. result mismatch: exp=%v got=%v", i, tt.expected, res))
	}
}
