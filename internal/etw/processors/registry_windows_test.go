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
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	valueTTL = time.Millisecond * 150
	valuePurgerInterval = time.Millisecond * 300
}

func TestRegistryProcessor(t *testing.T) {
	var tests = []struct {
		name           string
		e              *event.Event
		setupProcessor func(Processor)
		hsnap          func() *handle.SnapshotterMock
		assertions     func(*event.Event, *testing.T, *handle.SnapshotterMock, Processor)
	}{
		{
			"process KCB rundown",
			&event.Event{
				Type:     event.RegKCBRundown,
				Category: event.Registry,
				Params: event.Params{
					params.RegPath:      {Name: params.RegPath, Type: params.UnicodeString, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`},
					params.RegKeyHandle: {Name: params.RegKeyHandle, Type: params.Uint64, Value: uint64(18446666033549154696)},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				registryProcessor := p.(*registryProcessor)
				assert.Contains(t, registryProcessor.keys, uint64(18446666033549154696))
				assert.Equal(t, `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`, registryProcessor.keys[18446666033549154696])
			},
		},
		{
			"process delete KCB",
			&event.Event{
				Type:     event.RegDeleteKCB,
				Category: event.Registry,
				Params: event.Params{
					params.RegPath:      {Name: params.RegPath, Type: params.UnicodeString, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`},
					params.RegKeyHandle: {Name: params.RegKeyHandle, Type: params.Uint64, Value: uint64(18446666033549154696)},
				},
			},
			func(p Processor) {
				p.(*registryProcessor).keys[18446666033549154696] = `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				registryProcessor := p.(*registryProcessor)
				assert.Empty(t, registryProcessor.keys)
			},
		},
		{
			"full key name",
			&event.Event{
				Type:     event.RegOpenKey,
				Category: event.Registry,
				Params: event.Params{
					params.RegPath:      {Name: params.RegPath, Type: params.Key, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`},
					params.RegKeyHandle: {Name: params.RegKeyHandle, Type: params.Uint64, Value: uint64(0)},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\bthserv\Parameters`, e.GetParamAsString(params.RegPath))
			},
		},
		{
			"incomplete key name",
			&event.Event{
				Type:     event.RegOpenKey,
				Category: event.Registry,
				Params: event.Params{
					params.RegPath:      {Name: params.RegPath, Type: params.Key, Value: `Pid`},
					params.RegKeyHandle: {Name: params.RegKeyHandle, Type: params.Uint64, Value: uint64(18446666033549154696)},
				},
			},
			func(p Processor) {
				p.(*registryProcessor).keys[18446666033549154696] = `\REGISTRY\MACHINE\SYSTEM\Setup`
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`, e.GetParamAsString(params.RegPath))
			},
		},
		{
			"incomplete key name consult handle snapshotter",
			&event.Event{
				Type:     event.RegOpenKey,
				Category: event.Registry,
				PID:      23234,
				Params: event.Params{
					params.RegPath:      {Name: params.RegPath, Type: params.Key, Value: `Pid`},
					params.RegKeyHandle: {Name: params.RegKeyHandle, Type: params.Uint64, Value: uint64(18446666033549154696)},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				handles := []htypes.Handle{{Type: handle.Key, Name: `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`}}
				hsnap.On("FindHandles", uint32(23234)).Return(handles, nil)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				hsnap.AssertNumberOfCalls(t, "FindHandles", 1)
				assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`, e.GetParamAsString(params.RegPath))
			},
		},
		{
			"process registry set value",
			&event.Event{
				Type:     event.RegSetValue,
				Category: event.Registry,
				PID:      23234,
				Params: event.Params{
					params.RegPath:      {Name: params.RegPath, Type: params.Key, Value: `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Windows\Directory`},
					params.RegKeyHandle: {Name: params.RegKeyHandle, Type: params.Uint64, Value: uint64(0)},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Windows\Directory`, e.GetParamAsString(params.RegPath))
				assert.Equal(t, `REG_EXPAND_SZ`, e.GetParamAsString(params.RegValueType))
				assert.Equal(t, `%SystemRoot%`, e.GetParamAsString(params.RegData))
			},
		},
		{
			"process registry set value from internal event",
			&event.Event{
				Type:     event.RegSetValue,
				Category: event.Registry,
				PID:      23234,
				Params: event.Params{
					params.RegPath:      {Name: params.RegPath, Type: params.Key, Value: `\REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Control\Windows\Directory`},
					params.RegKeyHandle: {Name: params.RegKeyHandle, Type: params.Uint64, Value: uint64(0)},
				},
			},
			func(p Processor) {
				p.(*registryProcessor).values[23234] = map[string]*event.Event{
					"SessionId": {
						Type:      event.RegSetValueInternal,
						Timestamp: time.Now(),
						Params: event.Params{
							params.RegPath:      {Name: params.RegPath, Type: params.Key, Value: `\SessionId`},
							params.RegData:      {Name: params.RegData, Type: params.UnicodeString, Value: "{ABD9EA10-87F6-11EB-9ED5-645D86501328}"},
							params.RegValueType: {Name: params.RegValueType, Type: params.Enum, Value: uint32(1), Enum: key.RegistryValueTypes},
							params.RegKeyHandle: {Name: params.RegKeyHandle, Type: params.Uint64, Value: uint64(0)}},
					},
					"Directory": {
						Type:      event.RegSetValueInternal,
						Timestamp: time.Now(),
						Params: event.Params{
							params.RegPath:      {Name: params.RegPath, Type: params.Key, Value: `\Directory`},
							params.RegData:      {Name: params.RegData, Type: params.UnicodeString, Value: "%SYSTEMROOT%"},
							params.RegValueType: {Name: params.RegValueType, Type: params.Enum, Value: uint32(2), Enum: key.RegistryValueTypes},
							params.RegKeyHandle: {Name: params.RegKeyHandle, Type: params.Uint64, Value: uint64(0)}},
					},
				}
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Windows\Directory`, e.GetParamAsString(params.RegPath))
				assert.Equal(t, `REG_EXPAND_SZ`, e.GetParamAsString(params.RegValueType))
				assert.Equal(t, `%SYSTEMROOT%`, e.GetParamAsString(params.RegData))
				assert.Equal(t, p.(*registryProcessor).valuesSize(23234), 1)
				time.Sleep(time.Millisecond * 500)
				assert.Equal(t, p.(*registryProcessor).valuesSize(23234), 0)
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
