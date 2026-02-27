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

package filter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/stretchr/testify/require"
)

func TestGetFileInfo(t *testing.T) {
	path, err := os.Executable()
	require.NoError(t, err)

	var tests = []struct {
		e   *event.Event
		f   func(*testing.T, *event.Event)
		fld fields.Field
	}{
		{
			e: &event.Event{
				Name: "CreateFile",
				Params: map[string]*event.Param{
					params.FilePath: {Name: params.FilePath, Type: params.UnicodeString, Value: path},
				},
			},
			f: func(t *testing.T, e *event.Event) {
				require.True(t, e.Params.MustGetBool(params.FileIsExecutable))
			},
			fld: fields.FileIsExecutable,
		},
		{
			e: &event.Event{
				Name: "CreateFile",
				Params: map[string]*event.Param{
					params.FilePath: {Name: params.FilePath, Type: params.UnicodeString, Value: filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll")},
				},
			},
			f: func(t *testing.T, e *event.Event) {
				require.True(t, e.Params.MustGetBool(params.FileIsDLL))
			},
			fld: fields.ModuleIsDLL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.e.GetParamAsString(params.FilePath), func(t *testing.T) {
			v, err := getFileInfo(tt.fld, tt.e)
			require.NotNil(t, v)
			require.NoError(t, err)
			if tt.f != nil {
				tt.f(t, tt.e)
			}
		})
	}
}
