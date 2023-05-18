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

package kevent

import (
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBacklog(t *testing.T) {
	q := NewQueue(10)
	b := NewBacklog(q)

	e := &Kevent{
		Type:     ktypes.CreateHandle,
		Tid:      2484,
		PID:      859,
		Delayed:  true,
		Category: ktypes.Handle,
		Kparams: Kparams{
			kparams.HandleID:           {Name: kparams.HandleID, Type: kparams.Uint32, Value: uint32(21)},
			kparams.HandleObjectTypeID: {Name: kparams.HandleObjectTypeID, Type: kparams.AnsiString, Value: "Key"},
			kparams.HandleObject:       {Name: kparams.HandleObject, Type: kparams.Uint64, Value: uint64(18446692422059208560)},
			kparams.HandleObjectName:   {Name: kparams.HandleObjectName, Type: kparams.UnicodeString, Value: ""},
		},
		Metadata: make(Metadata),
	}

	require.NoError(t, b.Process(e))
	require.Equal(t, 1, b.Size())

	e1 := &Kevent{
		Type:     ktypes.CloseHandle,
		Tid:      2484,
		PID:      859,
		Category: ktypes.Handle,
		Kparams: Kparams{
			kparams.HandleID:           {Name: kparams.HandleID, Type: kparams.Uint32, Value: uint32(21)},
			kparams.HandleObjectTypeID: {Name: kparams.HandleObjectTypeID, Type: kparams.AnsiString, Value: "Key"},
			kparams.HandleObject:       {Name: kparams.HandleObject, Type: kparams.Uint64, Value: uint64(18446692422059208560)},
			kparams.HandleObjectName:   {Name: kparams.HandleObjectName, Type: kparams.UnicodeString, Value: `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`},
		},
		Metadata: make(Metadata),
	}

	require.NoError(t, b.Process(e1))
	require.Equal(t, 0, b.Size())
	ev := <-q.Events()
	require.NotNil(t, ev)
	assert.False(t, ev.Delayed)
	assert.Equal(t, `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`, ev.GetParamAsString(kparams.HandleObjectName))
}
