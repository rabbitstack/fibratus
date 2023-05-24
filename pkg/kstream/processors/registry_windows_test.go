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
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRegistryProcessor(t *testing.T) {
	var tests = []struct {
		name           string
		e              *kevent.Kevent
		setupProcessor func(Processor)
		hsnap          func() *handle.SnapshotterMock
		assertions     func(*kevent.Kevent, *testing.T, *handle.SnapshotterMock, Processor)
	}{
		{
			"process KCB rundown",
			&kevent.Kevent{
				Type:     ktypes.RegKCBRundown,
				Category: ktypes.Registry,
				Kparams: kevent.Kparams{
					kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.UnicodeString, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`},
					kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.Uint64, Value: uint64(18446666033549154696)},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				registryProcessor := p.(*registryProcessor)
				assert.Contains(t, registryProcessor.keys, uint64(18446666033549154696))
				assert.Equal(t, `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`, registryProcessor.keys[18446666033549154696])
			},
		},
		{
			"process delete KCB",
			&kevent.Kevent{
				Type:     ktypes.RegDeleteKCB,
				Category: ktypes.Registry,
				Kparams: kevent.Kparams{
					kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.UnicodeString, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`},
					kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.Uint64, Value: uint64(18446666033549154696)},
				},
			},
			func(p Processor) {
				p.(*registryProcessor).keys[18446666033549154696] = `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				registryProcessor := p.(*registryProcessor)
				assert.Empty(t, registryProcessor.keys)
			},
		},
		{
			"full key name",
			&kevent.Kevent{
				Type:     ktypes.RegOpenKey,
				Category: ktypes.Registry,
				Kparams: kevent.Kparams{
					kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.Key, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`},
					kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.Uint64, Value: uint64(0)},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`, e.GetParamAsString(kparams.RegKeyName))
			},
		},
		{
			"incomplete key name",
			&kevent.Kevent{
				Type:     ktypes.RegOpenKey,
				Category: ktypes.Registry,
				Kparams: kevent.Kparams{
					kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.Key, Value: `Pid`},
					kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.Uint64, Value: uint64(18446666033549154696)},
				},
			},
			func(p Processor) {
				p.(*registryProcessor).keys[18446666033549154696] = `\REGISTRY\MACHINE\SYSTEM\Setup`
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`, e.GetParamAsString(kparams.RegKeyName))
			},
		},
		{
			"incomplete key name consult handle snapshotter",
			&kevent.Kevent{
				Type:     ktypes.RegOpenKey,
				Category: ktypes.Registry,
				PID:      23234,
				Kparams: kevent.Kparams{
					kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.Key, Value: `Pid`},
					kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.Uint64, Value: uint64(18446666033549154696)},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				handles := []htypes.Handle{{Type: handle.Key, Name: `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`}}
				hsnap.On("FindHandles", uint32(23234)).Return(handles, nil)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				hsnap.AssertNumberOfCalls(t, "FindHandles", 1)
				assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`, e.GetParamAsString(kparams.RegKeyName))
			},
		},
		{
			"process registry set value",
			&kevent.Kevent{
				Type:     ktypes.RegSetValue,
				Category: ktypes.Registry,
				PID:      23234,
				Kparams: kevent.Kparams{
					kparams.RegKeyName:   {Name: kparams.RegKeyName, Type: kparams.Key, Value: `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Windows\Directory`},
					kparams.RegKeyHandle: {Name: kparams.RegKeyHandle, Type: kparams.Uint64, Value: uint64(0)},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Windows\Directory`, e.GetParamAsString(kparams.RegKeyName))
				assert.Equal(t, `REG_EXPAND_SZ`, e.GetParamAsString(kparams.RegValueType))
				assert.Equal(t, `%SystemRoot%`, e.GetParamAsString(kparams.RegValue))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hsnap := tt.hsnap()
			p := newRegistryProcessor(hsnap)
			if tt.setupProcessor != nil {
				tt.setupProcessor(p)
			}
			var err error
			tt.e, _, err = p.ProcessEvent(tt.e)
			require.NoError(t, err)
			tt.assertions(tt.e, t, hsnap, p)
		})
	}
}
