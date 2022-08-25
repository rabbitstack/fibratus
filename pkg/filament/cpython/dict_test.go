//go:build filament && windows
// +build filament,windows

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

package cpython

import (
	"github.com/magiconair/properties/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDict(t *testing.T) {
	t.SkipNow()
	dict := NewDict()
	require.False(t, dict.IsNull())

	dict.Insert(PyUnicodeFromString("filename"), PyUnicodeFromString("C:\\Windows\\System32\\kernel32.dll"))
	v := dict.Get(PyUnicodeFromString("filename"))
	require.NotNil(t, v)

	assert.Equal(t, `C:\Windows\System32\kernel32.dll`, v.String())
}
