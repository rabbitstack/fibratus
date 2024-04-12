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
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
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
		e          *kevent.Kevent
		psnap      func() *ps.SnapshotterMock
		assertions func(*kevent.Kevent, *testing.T, *ps.SnapshotterMock)
	}{
		{
			"load new image",
			&kevent.Kevent{
				Type: ktypes.LoadImage,
				Kparams: kevent.Kparams{
					kparams.ImageFilename:       {Name: kparams.ImageFilename, Type: kparams.UnicodeString, Value: filepath.Join(os.Getenv("windir"), "System32", "kernel32.dll")},
					kparams.ProcessID:           {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1023)},
					kparams.ImageCheckSum:       {Name: kparams.ImageCheckSum, Type: kparams.Uint32, Value: uint32(2323432)},
					kparams.ImageBase:           {Name: kparams.ImageBase, Type: kparams.Address, Value: uint64(0x7ffb313833a3)},
					kparams.ImageSignatureType:  {Name: kparams.ImageSignatureType, Type: kparams.Enum, Value: uint32(1), Enum: signature.Types},
					kparams.ImageSignatureLevel: {Name: kparams.ImageSignatureLevel, Type: kparams.Enum, Value: uint32(4), Enum: signature.Levels},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("AddModule", mock.Anything).Return(nil)
				return psnap
			},
			func(e *kevent.Kevent, t *testing.T, psnap *ps.SnapshotterMock) {
				psnap.AssertNumberOfCalls(t, "AddModule", 1)
				// should get the signature verified
				assert.Equal(t, "EMBEDDED", e.GetParamAsString(kparams.ImageSignatureType))
				assert.Equal(t, "AUTHENTICODE", e.GetParamAsString(kparams.ImageSignatureLevel))
			},
		},
		{
			"unload image",
			&kevent.Kevent{
				Type: ktypes.UnloadImage,
				Kparams: kevent.Kparams{
					kparams.ImageFilename:       {Name: kparams.ImageFilename, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\kernel32.dll"},
					kparams.ProcessName:         {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "csrss.exe"},
					kparams.ProcessID:           {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(676)},
					kparams.ImageBase:           {Name: kparams.ImageBase, Type: kparams.Address, Value: uint64(0xfffb313833a3)},
					kparams.ImageSignatureType:  {Name: kparams.ImageSignatureType, Type: kparams.Enum, Value: uint32(0), Enum: signature.Types},
					kparams.ImageSignatureLevel: {Name: kparams.ImageSignatureLevel, Type: kparams.Enum, Value: uint32(0), Enum: signature.Levels},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("RemoveModule", uint32(676), "C:\\Windows\\system32\\kernel32.dll").Return(nil)
				psnap.On("FindModule", mock.Anything).Return(false, nil)
				return psnap
			},
			func(e *kevent.Kevent, t *testing.T, psnap *ps.SnapshotterMock) {
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
