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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplace(t *testing.T) {
	call := Replace{}
	_, ok := call.Call([]interface{}{"hello world", "hello "})
	assert.False(t, ok)

	res, ok := call.Call([]interface{}{"hello world", "hello", "hell"})
	assert.Equal(t, "hell world", res)
	assert.True(t, ok)

	res1, ok := call.Call([]interface{}{"hello world", "hello", "hell", "NO", "REPL"})
	assert.Equal(t, "hell world", res1)
	assert.True(t, ok)

	res2, ok := call.Call([]interface{}{"hello world", "hello", "hell", "hell", "heaven", "world", "brave"})
	assert.Equal(t, "heaven brave", res2)
	assert.True(t, ok)

	key, ok := call.Call([]interface{}{"HKEY_LOCAL_MACHINE\\SAM", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER\\Console", "HKCU"})
	assert.Equal(t, "HKLM\\SAM", key)
	assert.True(t, ok)

	key1, ok := call.Call([]interface{}{"HKEY_CURRENT_USER\\Console", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU"})
	assert.Equal(t, "HKCU\\Console", key1)
	assert.True(t, ok)
}
