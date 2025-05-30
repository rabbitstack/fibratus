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

package processors

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"testing"
)

func TestMemProcessor(t *testing.T) {
	base, err := windows.VirtualAlloc(0, 1024, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	require.NoError(t, err)
	defer func() {
		_ = windows.VirtualFree(base, 1024, windows.MEM_RELEASE)
	}()
	var tests = []struct {
		name       string
		e          *event.Event
		psnap      func() *ps.SnapshotterMock
		assertions func(*event.Event, *testing.T, *ps.SnapshotterMock)
	}{
		{
			"virtual alloc",
			&event.Event{
				Type:     event.VirtualAlloc,
				Category: event.Mem,
				Params: event.Params{
					params.MemRegionSize:  {Name: params.MemRegionSize, Type: params.Uint64, Value: uint64(1024)},
					params.MemBaseAddress: {Name: params.MemBaseAddress, Type: params.Address, Value: uint64(base)},
					params.MemAllocType:   {Name: params.MemAllocType, Type: params.Flags, Value: uint32(0x00001000 | 0x00002000), Flags: event.MemAllocationFlags},
					params.ProcessID:      {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("FindAndPut", mock.Anything).Return(&pstypes.PS{Name: "svchost.exe", Exe: "C:\\Windows\\System32\\svchost.exe"})
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				psnap.AssertNumberOfCalls(t, "FindAndPut", 1)
				assert.Equal(t, "PRIVATE", e.GetParamAsString(params.MemPageType))
				assert.Equal(t, "EXECUTE_READWRITE", e.GetParamAsString(params.MemProtect))
				assert.Equal(t, "RWX", e.GetParamAsString(params.MemProtectMask))
				assert.Equal(t, "svchost.exe", e.GetParamAsString(params.ProcessName))
				assert.Equal(t, "C:\\Windows\\System32\\svchost.exe", e.GetParamAsString(params.Exe))
			},
		},
		{
			"virtual free",
			&event.Event{
				Type:     event.VirtualFree,
				Category: event.Mem,
				Params: event.Params{
					params.MemRegionSize:  {Name: params.MemRegionSize, Type: params.Uint64, Value: uint64(1024)},
					params.MemBaseAddress: {Name: params.MemBaseAddress, Type: params.Address, Value: uint64(base)},
					params.MemAllocType:   {Name: params.MemAllocType, Type: params.Flags, Value: uint32(0x00008000), Flags: event.MemAllocationFlags},
					params.ProcessID:      {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("FindAndPut", mock.Anything).Return(&pstypes.PS{Name: "svchost.exe", Exe: "C:\\Windows\\System32\\svchost.exe"})
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				psnap.AssertNumberOfCalls(t, "FindAndPut", 1)
				assert.Equal(t, "svchost.exe", e.GetParamAsString(params.ProcessName))
				assert.Equal(t, "C:\\Windows\\System32\\svchost.exe", e.GetParamAsString(params.Exe))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			psnap := tt.psnap()
			p := newMemProcessor(psnap, va.NewRegionProber())
			var err error
			tt.e, _, err = p.ProcessEvent(tt.e)
			require.NoError(t, err)
			tt.assertions(tt.e, t, psnap)
		})
	}
}
