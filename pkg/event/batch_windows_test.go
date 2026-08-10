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

package event

import (
	"encoding/json"
	"github.com/magiconair/properties/assert"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"testing"
	"time"
)

func TestBatchMarshalJSON(t *testing.T) {
	evt := &Event{
		Type:        CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Params: Params{
			params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
			params.FileOperation: {Name: params.FileOperation, Type: params.AnsiString, Value: "open"},
			params.BasePrio:      {Name: params.BasePrio, Type: params.Int8, Value: int8(2)},
			params.PagePrio:      {Name: params.PagePrio, Type: params.Uint8, Value: uint8(2)},
		},
		Metadata: map[MetadataKey]any{"foo": "bar", "fooz": "baarz"},
		PS: &pstypes.PS{
			PID:       2436,
			Ppid:      6304,
			Name:      "firefox.exe",
			Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
			Cmdline:   `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
			Cwd:       `C:\Program Files\Mozilla Firefox\`,
			SID:       "archrabbit\\SYSTEM",
			Args:      []string{"-contentproc", `--channel=6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
			SessionID: 4,
			Envs:      map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
			Threads: map[uint32]pstypes.Thread{
				3453: {Tid: 3453, StartAddress: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
				3455: {Tid: 3455, StartAddress: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			},
			Handles: []htypes.Handle{
				{Num: windows.Handle(0xffffd105e9baaf70),
					Name:   `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`,
					Type:   "Key",
					Object: 777488883434455544,
					Pid:    uint32(1023),
				},
				{
					Num:  windows.Handle(0xffffd105e9adaf70),
					Name: `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`,
					Type: "ALPC Port",
					Pid:  uint32(1023),
					MD: &htypes.AlpcPortInfo{
						Seqno:   1,
						Context: 0x0,
						Flags:   0x0,
					},
					Object: 457488883434455544,
				},
				{
					Num:  windows.Handle(0xeaffd105e9adaf30),
					Name: `C:\Users\bunny`,
					Type: "File",
					Pid:  uint32(1023),
					MD: &htypes.FileInfo{
						IsDirectory: true,
					},
					Object: 357488883434455544,
				},
			},
		},
	}

	evt1 := &Event{
		Type:        CreateFile,
		Tid:         2484,
		PID:         459,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Params: Params{
			params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
			params.FileOperation: {Name: params.FileOperation, Type: params.AnsiString, Value: "open"},
			params.BasePrio:      {Name: params.BasePrio, Type: params.Int8, Value: int8(2)},
			params.PagePrio:      {Name: params.PagePrio, Type: params.Uint8, Value: uint8(2)},
		},
		Metadata: map[MetadataKey]any{"foo": "bar", "fooz": "baarz"},
		PS: &pstypes.PS{
			PID:       2436,
			Ppid:      6304,
			Name:      "firefox.exe",
			Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
			Cmdline:   `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
			Cwd:       `C:\Program Files\Mozilla Firefox\`,
			SID:       "archrabbit\\SYSTEM",
			Args:      []string{"-contentproc", `--channel=6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
			SessionID: 4,
			Envs:      map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
			Threads: map[uint32]pstypes.Thread{
				3453: {Tid: 3453, StartAddress: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
				3455: {Tid: 3455, StartAddress: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			},
			Handles: []htypes.Handle{
				{Num: windows.Handle(0xffffd105e9baaf70),
					Name:   `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`,
					Type:   "Key",
					Object: 777488883434455544,
					Pid:    uint32(1023),
				},
				{
					Num:  windows.Handle(0xffffd105e9adaf70),
					Name: `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`,
					Type: "ALPC Port",
					Pid:  uint32(1023),
					MD: &htypes.AlpcPortInfo{
						Seqno:   1,
						Context: 0x0,
						Flags:   0x0,
					},
					Object: 457488883434455544,
				},
				{
					Num:  windows.Handle(0xeaffd105e9adaf30),
					Name: `C:\Users\bunny`,
					Type: "File",
					Pid:  uint32(1023),
					MD: &htypes.FileInfo{
						IsDirectory: true,
					},
					Object: 357488883434455544,
				},
			},
		},
	}

	evt2 := &Event{
		Type:        CreateFile,
		Tid:         2484,
		PID:         829,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Params: Params{
			params.FileObject:    {Name: params.FileObject, Type: params.Uint64, Value: uint64(12456738026482168384)},
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			params.FileType:      {Name: params.FileType, Type: params.AnsiString, Value: "file"},
			params.FileOperation: {Name: params.FileOperation, Type: params.AnsiString, Value: "open"},
			params.BasePrio:      {Name: params.BasePrio, Type: params.Int8, Value: int8(2)},
			params.PagePrio:      {Name: params.PagePrio, Type: params.Uint8, Value: uint8(2)},
		},
		Metadata: map[MetadataKey]any{"foo": "bar", "fooz": "baarz"},
		PS: &pstypes.PS{
			PID:       829,
			Ppid:      6304,
			Name:      "firefox.exe",
			Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
			Cmdline:   `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
			Cwd:       `C:\Program Files\Mozilla Firefox\`,
			SID:       "archrabbit\\SYSTEM",
			Args:      []string{"-contentproc", `--channel=6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
			SessionID: 4,
			Envs:      map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
			Threads: map[uint32]pstypes.Thread{
				3453: {Tid: 3453, StartAddress: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
				3455: {Tid: 3455, StartAddress: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			},
			Handles: []htypes.Handle{
				{Num: windows.Handle(0xffffd105e9baaf70),
					Name:   `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{b677c565-6ca5-45d3-b618-736b4e09b036}`,
					Type:   "Key",
					Object: 777488883434455544,
					Pid:    uint32(1023),
				},
				{
					Num:  windows.Handle(0xffffd105e9adaf70),
					Name: `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`,
					Type: "ALPC Port",
					Pid:  uint32(1023),
					MD: &htypes.AlpcPortInfo{
						Seqno:   1,
						Context: 0x0,
						Flags:   0x0,
					},
					Object: 457488883434455544,
				},
				{
					Num:  windows.Handle(0xeaffd105e9adaf30),
					Name: `C:\Users\bunny`,
					Type: "File",
					Pid:  uint32(1023),
					MD: &htypes.FileInfo{
						IsDirectory: true,
					},
					Object: 357488883434455544,
				},
			},
		},
	}

	b := NewBatch(evt, evt1, evt2)
	require.Equal(t, int64(3), b.Len())

	buf := b.MarshalJSON()
	var evts []*Event

	err := json.Unmarshal(buf, &evts)
	require.NoError(t, err)
	require.Len(t, evts, 3)

	assert.Equal(t, uint32(859), evts[0].PID)
	assert.Equal(t, uint32(459), evts[1].PID)
	assert.Equal(t, uint32(829), evts[2].PID)
}
