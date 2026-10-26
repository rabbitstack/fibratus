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
	"os"
	"path/filepath"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestModuleProcessor(t *testing.T) {
	var tests = []struct {
		name       string
		e          *event.Event
		psnap      func() *ps.SnapshotterMock
		assertions func(*event.Event, *testing.T, *ps.SnapshotterMock)
	}{
		{
			"load new module",
			&event.Event{
				Type: event.LoadModule,
				Params: event.ParamsOf(
					event.NewParam(params.ModulePath, params.String, params.Str(filepath.Join(os.Getenv("windir"), "System32", "kernel32.dll"))),
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(1023))),
					event.NewParam(params.ModuleCheckSum, params.Uint32, params.U32(uint32(2323432))),
					event.NewParam(params.ModuleBase, params.Address, params.U64(uint64(0x7ffb313833a3))),
					event.NewParam(params.ModuleSignatureType, params.Enum, params.U32(uint32(1)), event.WithEnum(signature.Types)),
					event.NewParam(params.ModuleSignatureLevel, params.Enum, params.U32(uint32(4)), event.WithEnum(signature.Levels)),
				),
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("AddModule", mock.Anything).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				psnap.AssertNumberOfCalls(t, "AddModule", 1)
				// should get the signature verified
				assert.Equal(t, "EMBEDDED", e.GetParamAsString(params.ModuleSignatureType))
				assert.Equal(t, "AUTHENTICODE", e.GetParamAsString(params.ModuleSignatureLevel))
			},
		},
		{
			"parse module characteristics",
			&event.Event{
				Type: event.LoadModule,
				Params: event.ParamsOf(
					event.NewParam(params.ModulePath, params.String, params.Str("../_fixtures/mscorlib.dll")),
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(1023))),
					event.NewParam(params.ModuleCheckSum, params.Uint32, params.U32(uint32(2323432))),
					event.NewParam(params.ModuleBase, params.Address, params.U64(uint64(0x7ffb313833a3))),
					event.NewParam(params.ModuleSignatureType, params.Enum, params.U32(uint32(1)), event.WithEnum(signature.Types)),
					event.NewParam(params.ModuleSignatureLevel, params.Enum, params.U32(uint32(4)), event.WithEnum(signature.Levels)),
				),
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("AddModule", mock.Anything).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				psnap.AssertNumberOfCalls(t, "AddModule", 1)
			},
		},
		{
			"unload module",
			&event.Event{
				Type: event.UnloadModule,
				Params: event.ParamsOf(
					event.NewParam(params.ModulePath, params.String, params.Str("C:\\Windows\\system32\\kernel32.dll")),
					event.NewParam(params.ProcessName, params.String, params.Str("csrss.exe")),
					event.NewParam(params.ProcessID, params.PID, params.U32(uint32(676))),
					event.NewParam(params.ModuleBase, params.Address, params.U64(uint64(0xfffb313833a3))),
					event.NewParam(params.ModuleSignatureType, params.Enum, params.U32(uint32(0)), event.WithEnum(signature.Types)),
					event.NewParam(params.ModuleSignatureLevel, params.Enum, params.U32(uint32(0)), event.WithEnum(signature.Levels)),
				),
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
			p := newModuleProcessor(psnap)
			var err error
			tt.e, _, err = p.ProcessEvent(tt.e)
			require.NoError(t, err)
			tt.assertions(tt.e, t, psnap)
		})
	}
}
