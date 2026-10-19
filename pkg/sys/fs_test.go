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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// payload returns n deterministic, non-repeating-looking bytes so that
// offset mistakes between the probe read and the remainder read show up.
func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251) // prime modulus avoids aligning with power-of-two buffers
	}
	return b
}

func writeTemp(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.bin")
	require.NoError(t, os.WriteFile(path, content, 0644))
	return path
}

func TestReadFile(t *testing.T) {
	var tests = []struct {
		name    string
		content []byte
		missing bool
		size    int
		err     error
		b       []byte
	}{
		{"read file", []byte("hello world"), false, 4096, nil, []byte("hello world")},
		{"empty file", []byte{}, false, 4096, nil, []byte{}},
		{"size smaller than file", []byte("hello world"), false, 5, nil, []byte("hello")},
		{"size equal to file", []byte("hello world"), false, 11, nil, []byte("hello world")},
		{"file larger than 1 MB", payload(1<<20 + 17), false, 4 << 20, nil, payload(1<<20 + 17)},
		{"missing file", nil, true, 4096, windows.ERROR_FILE_NOT_FOUND, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "missing.bin")
			if !tt.missing {
				path = writeTemp(t, tt.content)
			}
			b, err := ReadFile(path, tt.size, time.Second)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.b, b)
		})
	}
}

func TestReadFileWithPredicate(t *testing.T) {
	errRejected := errors.New("rejected by accept")

	var tests = []struct {
		name    string
		content []byte
		missing bool
		size    int
		probe   int

		// accept behaviour: nil accept disables the callback entirely
		useAccept bool
		acceptErr error

		err error
		b   []byte
		// expected len(head) passed to accept, -1 if accept must not be called
		headLen int
	}{
		{
			name: "no accept reads whole file", content: payload(5000),
			size: 1 << 20, probe: 1024,
			b: payload(5000), headLen: -1,
		},
		{
			name: "accept sees only probe bytes of a larger file", content: payload(5000),
			size: 1 << 20, probe: 1024, useAccept: true,
			b: payload(5000), headLen: 1024,
		},
		{
			name: "remainder read continues at the right offset", content: payload(3<<20 + 123),
			size: 8 << 20, probe: 1024, useAccept: true,
			b: payload(3<<20 + 123), headLen: 1024,
		},
		{
			name: "probe larger than file", content: payload(300),
			size: 1 << 20, probe: 1024, useAccept: true,
			b: payload(300), headLen: 300,
		},
		{
			name: "probe equal to file", content: payload(1024),
			size: 1 << 20, probe: 1024, useAccept: true,
			b: payload(1024), headLen: 1024,
		},
		{
			name: "zero probe size means single full read", content: payload(5000),
			size: 1 << 20, probe: 0, useAccept: true,
			b: payload(5000), headLen: 5000,
		},
		{
			name: "size caps the total", content: payload(5000),
			size: 2000, probe: 1024, useAccept: true,
			b: payload(2000), headLen: 1024,
		},
		{
			name: "size smaller than probe", content: payload(5000),
			size: 100, probe: 1024, useAccept: true,
			b: payload(100), headLen: 100,
		},
		{
			name: "accept error stops the read", content: payload(5000),
			size: 1 << 20, probe: 1024, useAccept: true, acceptErr: errRejected,
			err: errRejected, b: nil, headLen: 1024,
		},
		{
			name: "accept error on a file that fits in the probe", content: payload(100),
			size: 1 << 20, probe: 1024, useAccept: true, acceptErr: errRejected,
			err: errRejected, b: nil, headLen: 100,
		},
		{
			// empty files short-circuit before any read, so accept never runs.
			// Callers must therefore not rely on accept to detect empty files.
			name: "empty file skips accept", content: []byte{},
			size: 1 << 20, probe: 1024, useAccept: true,
			b: []byte{}, headLen: -1,
		},
		{
			name: "missing file", missing: true,
			size: 1 << 20, probe: 1024, useAccept: true,
			err: windows.ERROR_FILE_NOT_FOUND, b: nil, headLen: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "missing.bin")
			if !tt.missing {
				path = writeTemp(t, tt.content)
			}

			var (
				calls int
				head  []byte
			)
			var accept func([]byte) error
			if tt.useAccept {
				accept = func(h []byte) error {
					calls++
					head = append([]byte(nil), h...) // copy: h aliases the read buffer
					return tt.acceptErr
				}
			}

			b, err := ReadFileWithPredicate(path, tt.size, tt.probe, time.Second, accept)
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.b, b)

			if tt.headLen < 0 {
				require.Zero(t, calls, "accept must not be called")
				return
			}
			require.Equal(t, 1, calls, "accept must be called exactly once")
			require.Len(t, head, tt.headLen)
			// the head must be a prefix of the file, not garbage from a later offset
			require.Equal(t, tt.content[:tt.headLen], head)
		})
	}
}

// A file that is open for exclusive writing elsewhere must still be readable,
// because the store opens with FILE_SHARE_READ|WRITE|DELETE. This mirrors the
// file-create-event case where the writer is still active.
func TestReadFileProbeWhileWriterHoldsHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "writer.bin")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer f.Close()
	_, err = f.Write(payload(2048))
	require.NoError(t, err)

	b, err := ReadFileWithPredicate(path, 1<<20, 1024, time.Second, func([]byte) error { return nil })
	require.NoError(t, err)
	require.Equal(t, payload(2048), b)
}
