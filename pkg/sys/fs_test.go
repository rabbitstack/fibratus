//go:build windows

/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package sys

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReadFile(t *testing.T) {
	var tests = []struct {
		name string
		f    func() (string, error)
		err  error
		b    []byte
	}{
		{
			"read file",
			func() (string, error) {
				path := filepath.Join(t.TempDir(), "test.txt")

				return path, os.WriteFile(path, []byte("hello world"), 0644)
			},
			nil,
			[]byte{104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := tt.f()
			require.NoError(t, err)
			defer os.Remove(path)
			b, err := ReadFile(path, 4096, time.Second*1)
			require.Equal(t, tt.err, err)
			require.Equal(t, tt.b, b)
		})
	}
}
