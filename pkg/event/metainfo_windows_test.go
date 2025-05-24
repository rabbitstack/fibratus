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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEventNameToType(t *testing.T) {
	typ := NameToType("CreateProcess")

	assert.Equal(t, CreateProcess, typ)

	typ = NameToType("CreateRemoteThread")
	assert.Equal(t, UnknownType, typ)
}

func TestEventToEventInfo(t *testing.T) {
	info := TypeToEventInfo(CreateProcess)

	assert.Equal(t, "CreateProcess", info.Name)
	assert.Equal(t, Process, info.Category)
	assert.Equal(t, "Creates a new process and its primary thread", info.Description)

	info = TypeToEventInfo(UnknownType)
	assert.Equal(t, "N/A", info.Name)
	assert.Equal(t, Unknown, info.Category)
	assert.Empty(t, info.Description)
}
