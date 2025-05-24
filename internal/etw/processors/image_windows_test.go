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

package processors

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestImageProcessor(t *testing.T) {
	var tests = []struct {
		name       string
		e          *event.Event
		psnap      func() *ps.SnapshotterMock
		assertions func(*event.Event, *testing.T, *ps.SnapshotterMock)
	}{
		{
			"load new image",
			&event.Event{
				Type: event.LoadImage,
				Params: event.Params{
					params.ImagePath:           {Name: params.ImagePath, Type: params.UnicodeString, Value: filepath.Join(os.Getenv("windir"), "System32", "kernel32.dll")},
					params.ProcessID:           {Name: params.ProcessID, Type: params.PID, Value: uint32(1023)},
					params.ImageCheckSum:       {Name: params.ImageCheckSum, Type: params.Uint32, Value: uint32(2323432)},
					params.ImageBase:           {Name: params.ImageBase, Type: params.Address, Value: uint64(0x7ffb313833a3)},
					params.ImageSignatureType:  {Name: params.ImageSignatureType, Type: params.Enum, Value: uint32(1), Enum: signature.Types},
					params.ImageSignatureLevel: {Name: params.ImageSignatureLevel, Type: params.Enum, Value: uint32(4), Enum: signature.Levels},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("AddModule", mock.Anything).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				psnap.AssertNumberOfCalls(t, "AddModule", 1)
				// should get the signature verified
				assert.Equal(t, "EMBEDDED", e.GetParamAsString(params.ImageSignatureType))
				assert.Equal(t, "AUTHENTICODE", e.GetParamAsString(params.ImageSignatureLevel))
			},
		},
		{
			"parse image characteristics",
			&event.Event{
				Type: event.LoadImage,
				Params: event.Params{
					params.ImagePath:           {Name: params.ImagePath, Type: params.UnicodeString, Value: "../_fixtures/mscorlib.dll"},
					params.ProcessID:           {Name: params.ProcessID, Type: params.PID, Value: uint32(1023)},
					params.ImageCheckSum:       {Name: params.ImageCheckSum, Type: params.Uint32, Value: uint32(2323432)},
					params.ImageBase:           {Name: params.ImageBase, Type: params.Address, Value: uint64(0x7ffb313833a3)},
					params.ImageSignatureType:  {Name: params.ImageSignatureType, Type: params.Enum, Value: uint32(1), Enum: signature.Types},
					params.ImageSignatureLevel: {Name: params.ImageSignatureLevel, Type: params.Enum, Value: uint32(4), Enum: signature.Levels},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("AddModule", mock.Anything).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				psnap.AssertNumberOfCalls(t, "AddModule", 1)
				// should be enriched with image characteristics params
				assert.True(t, e.Params.MustGetBool(params.FileIsDLL))
				assert.True(t, e.Params.MustGetBool(params.FileIsDotnet))
				assert.False(t, e.Params.MustGetBool(params.FileIsExecutable))
				assert.False(t, e.Params.MustGetBool(params.FileIsDriver))
			},
		},
		{
			"unload image",
			&event.Event{
				Type: event.UnloadImage,
				Params: event.Params{
					params.ImagePath:           {Name: params.ImagePath, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\kernel32.dll"},
					params.ProcessName:         {Name: params.ProcessName, Type: params.AnsiString, Value: "csrss.exe"},
					params.ProcessID:           {Name: params.ProcessID, Type: params.PID, Value: uint32(676)},
					params.ImageBase:           {Name: params.ImageBase, Type: params.Address, Value: uint64(0xfffb313833a3)},
					params.ImageSignatureType:  {Name: params.ImageSignatureType, Type: params.Enum, Value: uint32(0), Enum: signature.Types},
					params.ImageSignatureLevel: {Name: params.ImageSignatureLevel, Type: params.Enum, Value: uint32(0), Enum: signature.Levels},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("RemoveModule", uint32(676), va.Address(0xfffb313833a3)).Return(nil)
				psnap.On("FindModule", mock.Anything).Return(false, nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				psnap.AssertNumberOfCalls(t, "RemoveModule", 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			psnap := tt.psnap()
			p := newImageProcessor(psnap)
			var err error
			tt.e, _, err = p.ProcessEvent(tt.e)
			require.NoError(t, err)
			tt.assertions(tt.e, t, psnap)
		})
	}
}
