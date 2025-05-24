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
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestParams(t *testing.T) {
	pars := Params{
		params.FileObject:        {Name: params.FileObject, Type: params.Uint64, Value: uint64(18446738026482168384)},
		params.ThreadID:          {Name: params.ThreadID, Type: params.Uint32, Value: uint32(1484)},
		params.FileCreateOptions: {Name: params.FileCreateOptions, Type: params.Uint32, Value: uint32(1223456)},
		params.FilePath:          {Name: params.FilePath, Type: params.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll"},
		params.FileShareMask:     {Name: params.FileShareMask, Type: params.Uint32, Value: uint32(5)},
	}

	assert.True(t, pars.Contains(params.FileObject))
	assert.False(t, pars.Contains(params.FileOffset))

	filename, err := pars.GetString(params.FilePath)
	require.NoError(t, err)
	assert.Equal(t, "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll", filename)

	_, err = pars.GetString(params.FileObject)
	require.Error(t, err)

	assert.Equal(t, 5, pars.Len())

	pars.Remove(params.ThreadID)

	assert.False(t, pars.Contains(params.ThreadID))
	assert.Equal(t, 4, pars.Len())

	require.NoError(t, pars.Set(params.FileShareMask, uint32(5), params.Enum))

	require.NoError(t, pars.SetValue(params.FilePath, "\\Device\\HarddiskVolume2\\Windows\\system32\\KERNEL32.dll"))
	filename1, err := pars.GetString(params.FilePath)
	require.NoError(t, err)
	assert.Equal(t, "\\Device\\HarddiskVolume2\\Windows\\system32\\KERNEL32.dll", filename1)
}
