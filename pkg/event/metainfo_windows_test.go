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

package event

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseType(t *testing.T) {
	var tests = []struct {
		name         string
		expectedType Type
	}{
		{"CreateProcess", CreateProcess},
		{"CreateRemoteThread", Unknown},
		{"FileOpEnd", FileOpEnd},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			etype, _ := ParseType(tt.name)
			assert.Equal(t, tt.expectedType, etype)
		})
	}
}

func TestEventToEventInfo(t *testing.T) {
	info := GetTypeInfo(CreateProcess)

	assert.Equal(t, "CreateProcess", info.Name)
	assert.Equal(t, Process, info.Category)
	assert.Equal(t, "Creates a new process and its primary thread", info.Description)
}
