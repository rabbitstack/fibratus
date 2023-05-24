//go:build windows
// +build windows

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

package types

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"testing"
)

func TestMarshaller(t *testing.T) {
	h := Handle{
		Num:    windows.Handle(0xffffd105e9baaf70),
		Name:   `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`,
		Type:   "Key",
		Object: 777488883434455544,
		Pid:    uint32(1023),
	}
	buf := h.Marshal()

	clone := Handle{}
	err := clone.Unmarshal(buf)
	require.NoError(t, err)

	assert.Equal(t, windows.Handle(18446692422059208560), clone.Num)
	assert.Equal(t, "Key", clone.Type)
	assert.Equal(t, `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`, clone.Name)
	assert.Equal(t, uint32(1023), clone.Pid)
	assert.Equal(t, uint64(777488883434455544), clone.Object)

	h = Handle{
		Num:  windows.Handle(0xefffd105e9adaf70),
		Name: `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`,
		Type: "ALPC Port",
		Pid:  uint32(1023),
		MD: &AlpcPortInfo{
			Seqno:   1,
			Context: 0x0,
			Flags:   0x0,
		},
	}
	buf = h.Marshal()

	err = clone.Unmarshal(buf)
	require.NoError(t, err)

	assert.Equal(t, windows.Handle(0xefffd105e9adaf70), clone.Num)
	assert.Equal(t, "ALPC Port", clone.Type)
	assert.Equal(t, `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`, clone.Name)
	assert.Equal(t, uint32(1023), clone.Pid)
	assert.NotNil(t, clone.MD)
	assert.IsType(t, &AlpcPortInfo{}, clone.MD)
	alpcPortInfo := clone.MD.(*AlpcPortInfo)
	assert.Equal(t, uint32(1), alpcPortInfo.Seqno)
}
