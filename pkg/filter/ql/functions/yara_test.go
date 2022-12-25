//go:build yara
// +build yara

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
	"os"
	"testing"
)

func TestYara(t *testing.T) {
	var tests = []struct {
		args     []interface{}
		expected bool
	}{
		{
			[]interface{}{uint32(os.Getpid())},
			true,
		},
	}

	for i, tt := range tests {
		f := Yara{}
		res, _ := f.Call(tt.args)
		assert.Equal(t, tt.expected, res, fmt.Sprintf("%d. result mismatch: exp=%v got=%v", i, tt.expected, res))
	}
}
