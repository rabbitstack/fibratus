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
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHandleProcessor(t *testing.T) {
	var tests = []struct {
		name       string
		e          *kevent.Kevent
		hsnap      func() *handle.SnapshotterMock
		assertions func(*kevent.Kevent, *testing.T, *handle.SnapshotterMock)
	}{
		{
			"process create handle",
			&kevent.Kevent{
				Type:     ktypes.CreateHandle,
				Tid:      2484,
				PID:      859,
				Category: ktypes.Handle,
				Kparams: kevent.Kparams{
					kparams.HandleID:           {Name: kparams.HandleID, Type: kparams.Uint32, Value: uint32(21)},
					kparams.HandleObjectTypeID: {Name: kparams.HandleObjectTypeID, Type: kparams.AnsiString, Value: "Key"},
					kparams.HandleObject:       {Name: kparams.HandleObject, Type: kparams.Uint64, Value: uint64(18446692422059208560)},
					kparams.HandleObjectName:   {Name: kparams.HandleObjectName, Type: kparams.UnicodeString, Value: ""},
				},
				Metadata: make(kevent.Metadata),
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				hsnap.On("Write", mock.Anything).Return(nil)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock) {
				hsnap.AssertNumberOfCalls(t, "Write", 1)
			},
		},
		{
			"process close handle",
			&kevent.Kevent{
				Type:     ktypes.CloseHandle,
				Tid:      2484,
				PID:      859,
				Category: ktypes.Handle,
				Kparams: kevent.Kparams{
					kparams.HandleID:           {Name: kparams.HandleID, Type: kparams.Uint32, Value: uint32(21)},
					kparams.HandleObjectTypeID: {Name: kparams.HandleObjectTypeID, Type: kparams.AnsiString, Value: "Key"},
					kparams.HandleObject:       {Name: kparams.HandleObject, Type: kparams.Uint64, Value: uint64(18446692422059208560)},
					kparams.HandleObjectName:   {Name: kparams.HandleObjectName, Type: kparams.UnicodeString, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`},
				},
				Metadata: make(kevent.Metadata),
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				hsnap.On("Remove", mock.Anything).Return(nil)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock) {
				assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`, e.GetParamAsString(kparams.HandleObjectName))
				hsnap.AssertNumberOfCalls(t, "Remove", 1)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hsnap := tt.hsnap()
			psnap := new(ps.SnapshotterMock)
			p := newHandleProcessor(hsnap, psnap, fs.NewDevMapper(), fs.NewDevPathResolver())
			var err error
			tt.e, _, err = p.ProcessEvent(tt.e)
			require.NoError(t, err)
			tt.assertions(tt.e, t, hsnap)
		})
	}
}
