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

package kevent

import (
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestKparams(t *testing.T) {
	kpars := Kparams{
		kparams.FileObject:        {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(18446738026482168384)},
		kparams.ThreadID:          {Name: kparams.ThreadID, Type: kparams.Uint32, Value: uint32(1484)},
		kparams.FileCreateOptions: {Name: kparams.FileCreateOptions, Type: kparams.Uint32, Value: uint32(1223456)},
		kparams.FileName:          {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll"},
		kparams.FileShareMask:     {Name: kparams.FileShareMask, Type: kparams.Uint32, Value: uint32(5)},
	}

	assert.True(t, kpars.Contains(kparams.FileObject))
	assert.False(t, kpars.Contains(kparams.FileOffset))

	filename, err := kpars.GetString(kparams.FileName)
	require.NoError(t, err)
	assert.Equal(t, "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll", filename)

	filename, err = kpars.GetString(kparams.FileObject)
	require.Error(t, err)

	assert.Equal(t, 5, kpars.Len())

	kpars.Remove(kparams.ThreadID)

	assert.False(t, kpars.Contains(kparams.ThreadID))
	assert.Equal(t, 4, kpars.Len())

	require.NoError(t, kpars.Set(kparams.FileShareMask, fs.FileShareMode(5), kparams.Enum))

	filemode, err := kpars.Get(kparams.FileShareMask)
	require.NoError(t, err)
	mode := filemode.(fs.FileShareMode)

	assert.Equal(t, "r-d", mode.String())
}
