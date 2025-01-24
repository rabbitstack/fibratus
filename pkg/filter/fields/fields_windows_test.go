/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package fields

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestIsField(t *testing.T) {
	var tests = []struct {
		name    string
		isField bool
	}{
		{"ps.pid", true},
		{"ps.none", false},
		{"ps.envs[ALLUSERSPROFILE]", false},
		{"kevt.arg", true},
		{"thread._callstack", true},
		{"kevt._callstack", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.isField, IsField(tt.name))
		})
	}
}

func TestIsDeprecated(t *testing.T) {
	deprecated, d := IsDeprecated(PsSiblingPid)
	assert.True(t, deprecated)
	assert.NotNil(t, d)
}
