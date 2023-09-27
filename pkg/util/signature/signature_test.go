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

package signature

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"testing"
)

func TestSignature(t *testing.T) {
	executable, err := os.Executable()
	require.NoError(t, err)

	var tests = []struct {
		name     string
		filename string
		sigType  uint32
		sigLevel uint32
		err      error
	}{
		{
			"PE embedded signature",
			filepath.Join(os.Getenv("windir"), "System32", "kernel32.dll"),
			Embedded,
			AuthenticodeLevel,
			nil,
		},
		{
			"catalog signature",
			filepath.Join(os.Getenv("windir"), "notepad.exe"),
			Catalog,
			AuthenticodeLevel,
			nil,
		},
		{
			"unsigned binary",
			executable,
			None,
			UnsignedLevel,
			windows.ERROR_INVALID_PARAMETER,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := Check(tt.filename)
			assert.True(t, err == tt.err)
			if sig != nil {
				assert.Equal(t, tt.sigType, sig.Type)
				sig.Verify()
				assert.Equal(t, tt.sigLevel, sig.Level)
			}
		})
	}
}
