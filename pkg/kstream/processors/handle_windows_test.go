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
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type objectTypeStoreMock struct {
	mock.Mock
}

func (s *objectTypeStoreMock) FindByID(id uint8) string {
	args := s.Called(id)
	return args.String(0)
}

func (s *objectTypeStoreMock) TypeNames() []string {
	args := s.Called()
	return args.Get(0).([]string)
}

func (s *objectTypeStoreMock) RegisterType(id uint8, typ string) {}

func TestCloseHandle(t *testing.T) {
	objectTypeStore := new(objectTypeStoreMock)
	hsnapMock := new(handle.SnapshotterMock)
	devMapper := new(devMapperMock)
	deferredKevts := make(chan *kevent.Kevent, 1)

	kevt := &kevent.Kevent{
		Type:     ktypes.CloseHandle,
		Tid:      2484,
		PID:      859,
		Category: ktypes.Handle,
		Kparams: kevent.Kparams{
			kparams.HandleID:           {Name: kparams.HandleID, Type: kparams.Uint32, Value: uint32(21)},
			kparams.HandleObjectTypeID: {Name: kparams.HandleObjectTypeID, Type: kparams.Uint16, Value: uint16(23)},
			kparams.HandleObject:       {Name: kparams.HandleObject, Type: kparams.HexInt64, Value: kparams.Hex("ffffd105e9baaf70")},
			kparams.HandleObjectName:   {Name: kparams.HandleObjectName, Type: kparams.UnicodeString, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`},
		},
	}

	hsnapMock.On("Remove", kevt).Return(nil)

	hi := newHandleInterceptor(hsnapMock, objectTypeStore, devMapper, deferredKevts)

	objectTypeStore.On("FindByID", uint8(23)).Return(handle.Key)

	assert.Len(t, hi.(*handleInterceptor).objects, 0)

	_, _, err := hi.Intercept(kevt)
	require.NoError(t, err)

	keyName, err := kevt.Kparams.GetString(kparams.HandleObjectName)
	require.NoError(t, err)
	typ, err := kevt.Kparams.GetString(kparams.HandleObjectTypeName)
	require.NoError(t, err)
	assert.Equal(t, handle.Key, typ)
	assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`, keyName)
}

func TestHandleCoalescing(t *testing.T) {
	kevt := &kevent.Kevent{
		Type:     ktypes.CreateHandle,
		Tid:      2484,
		PID:      859,
		Category: ktypes.Handle,
		Kparams: kevent.Kparams{
			kparams.HandleID:           {Name: kparams.HandleID, Type: kparams.Uint32, Value: uint32(21)},
			kparams.HandleObjectTypeID: {Name: kparams.HandleObjectTypeID, Type: kparams.Uint16, Value: uint16(23)},
			kparams.HandleObject:       {Name: kparams.HandleObject, Type: kparams.HexInt64, Value: kparams.Hex("ffffd105e9baaf70")},
			kparams.HandleObjectName:   {Name: kparams.HandleObjectName, Type: kparams.UnicodeString, Value: ""},
		},
	}
	deferredKevts := make(chan *kevent.Kevent, 1)
	devMapper := new(devMapperMock)

	hsnapMock := new(handle.SnapshotterMock)
	objectTypeStore := new(objectTypeStoreMock)

	hsnapMock.On("Write", mock.Anything).Return(nil)
	hsnapMock.On("Remove", mock.Anything).Return(nil)

	hi := newHandleInterceptor(hsnapMock, objectTypeStore, devMapper, deferredKevts)

	objectTypeStore.On("FindByID", uint8(23)).Return(handle.Key)

	_, _, err := hi.Intercept(kevt)
	require.Error(t, err)
	require.True(t, kerrors.IsCancelUpstreamKevent(err))

	assert.Len(t, hi.(*handleInterceptor).objects, 1)

	kevt1 := &kevent.Kevent{
		Type:     ktypes.CloseHandle,
		Tid:      2484,
		PID:      859,
		Category: ktypes.Handle,
		Kparams: kevent.Kparams{
			kparams.HandleID:           {Name: kparams.HandleID, Type: kparams.Uint32, Value: uint32(21)},
			kparams.HandleObjectTypeID: {Name: kparams.HandleObjectTypeID, Type: kparams.Uint16, Value: uint16(23)},
			kparams.HandleObject:       {Name: kparams.HandleObject, Type: kparams.HexInt64, Value: kparams.Hex("ffffd105e9baaf70")},
			kparams.HandleObjectName:   {Name: kparams.HandleObjectName, Type: kparams.UnicodeString, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`},
		},
	}

	ckevt, _, err := hi.Intercept(kevt1)
	require.NoError(t, err)

	keyName, err := ckevt.Kparams.GetString(kparams.HandleObjectName)
	require.NoError(t, err)
	assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`, keyName)

	assert.Len(t, hi.(*handleInterceptor).objects, 0)

	dkevt := <-deferredKevts
	require.NotNil(t, dkevt)

	assert.Equal(t, ktypes.CreateHandle, dkevt.Type)

	keyName, err = dkevt.Kparams.GetString(kparams.HandleObjectName)
	require.NoError(t, err)
	assert.Equal(t, `HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`, keyName)
}

func init() {
	waitPeriod = time.Millisecond * 500
}

func TestHandleCoalescingWaiting(t *testing.T) {
	kevt := &kevent.Kevent{
		Type:      ktypes.CreateHandle,
		Tid:       2484,
		PID:       859,
		Timestamp: time.Now(),
		Category:  ktypes.Handle,
		Kparams: kevent.Kparams{
			kparams.HandleID:           {Name: kparams.HandleID, Type: kparams.Uint32, Value: uint32(21)},
			kparams.HandleObjectTypeID: {Name: kparams.HandleObjectTypeID, Type: kparams.Uint16, Value: uint16(23)},
			kparams.HandleObject:       {Name: kparams.HandleObject, Type: kparams.HexInt64, Value: kparams.Hex("ffffd105e9baaf70")},
			kparams.HandleObjectName:   {Name: kparams.HandleObjectName, Type: kparams.UnicodeString, Value: ""},
		},
	}

	deferredKevts := make(chan *kevent.Kevent, 1)

	devMapper := new(devMapperMock)
	objectTypeStore := new(objectTypeStoreMock)
	hsnapMock := new(handle.SnapshotterMock)

	hsnapMock.On("Write", mock.Anything).Return(nil)
	hsnapMock.On("Remove", mock.Anything).Return(nil)

	hi := newHandleInterceptor(hsnapMock, objectTypeStore, devMapper, deferredKevts)

	objectTypeStore.On("FindByID", uint8(23)).Return(handle.Key)

	_, _, err := hi.Intercept(kevt)
	require.Error(t, err)
	require.True(t, kerrors.IsCancelUpstreamKevent(err))

	assert.Len(t, hi.(*handleInterceptor).objects, 1)

	kevt1 := &kevent.Kevent{
		Type:     ktypes.CloseHandle,
		Tid:      2484,
		PID:      859,
		Category: ktypes.Handle,
		Kparams: kevent.Kparams{
			kparams.HandleID:           {Name: kparams.HandleID, Type: kparams.Uint32, Value: uint32(21)},
			kparams.HandleObjectTypeID: {Name: kparams.HandleObjectTypeID, Type: kparams.Uint16, Value: uint16(23)},
			kparams.HandleObject:       {Name: kparams.HandleObject, Type: kparams.HexInt64, Value: kparams.Hex("affdd155e9baaf70")},
			kparams.HandleObjectName:   {Name: kparams.HandleObjectName, Type: kparams.UnicodeString, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`},
		},
	}

	time.Sleep(time.Millisecond * 510)

	_, _, err = hi.Intercept(kevt1)
	require.NoError(t, err)

	assert.Len(t, hi.(*handleInterceptor).objects, 0)
}
