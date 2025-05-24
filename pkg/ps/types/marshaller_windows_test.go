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
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"golang.org/x/sys/windows"

	"github.com/rabbitstack/fibratus/pkg/cap/section"
	kcapver "github.com/rabbitstack/fibratus/pkg/cap/version"
	"github.com/rabbitstack/fibratus/pkg/pe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestPSMarshaler(t *testing.T) {
	n := time.Now()
	ps := &PS{
		PID:       2436,
		Ppid:      6304,
		Name:      "firefox.exe",
		Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
		Cmdline:   `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
		Cwd:       `C:\Program Files\Mozilla Firefox\`,
		SID:       "archrabbit\\SYSTEM",
		Args:      []string{"-contentproc", `--channel="6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
		SessionID: 4,
		Envs:      map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
		uuid:      123456789,
		StartTime: n,
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
		IsProtected: true,
		IsWOW64:     true,
		IsPackaged:  false,
	}

	b := ps.Marshal()
	sec := section.New(section.Process, kcapver.ProcessSecV4, 0, 0)
	clone, err := NewFromKcap(b, sec)
	require.NoError(t, err)

	assert.Equal(t, uint32(2436), clone.PID)
	assert.Equal(t, uint32(6304), clone.Ppid)
	assert.Equal(t, "firefox.exe", clone.Name)
	assert.Equal(t, uint64(123456789), clone.uuid)
	assert.True(t, n.Equal(clone.StartTime))
	assert.Equal(t, `C:\Program Files\Mozilla Firefox\firefox.exe`, clone.Exe)
	assert.Equal(t, `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`, clone.Cmdline)
	assert.Equal(t, `C:\Program Files\Mozilla Firefox\`, clone.Cwd)
	assert.Equal(t, "archrabbit\\SYSTEM", clone.SID)
	assert.Equal(t, []string{"-contentproc", `--channel="6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"}, clone.Args)
	assert.Equal(t, uint32(4), clone.SessionID)
	assert.Equal(t, map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"}, clone.Envs)
	assert.True(t, clone.IsProtected)
	assert.True(t, clone.IsWOW64)
	assert.False(t, clone.IsPackaged)

	require.Len(t, clone.Handles, 3)

	alpc := clone.Handles[1]
	assert.Equal(t, "ALPC Port", alpc.Type)
	assert.Equal(t, `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`, alpc.Name)
	assert.IsType(t, &htypes.AlpcPortInfo{}, alpc.MD)

	md := alpc.MD.(*htypes.AlpcPortInfo)
	assert.Equal(t, uint32(1), md.Seqno)
}

func TestPSMarshalerWithPE(t *testing.T) {
	n := time.Now()
	p := &pe.PE{
		NumberOfSections: 7,
		NumberOfSymbols:  10,
		EntryPoint:       "20110",
		ImageBase:        "140000000",
		LinkTime:         n,
		Sections: []pe.Sec{
			{Name: ".text", Size: 132608, Entropy: 6.368381, Md5: "db23dce3911a42e987041d98abd4f7cd"},
			{Name: ".rdata", Size: 35840, Entropy: 5.996976, Md5: "ffa5c960b421ca9887e54966588e97e8"},
		},
		Symbols:          []string{"SelectObject", "GetTextFaceW", "EnumFontsW", "TextOutW", "GetProcessHeap"},
		Imports:          []string{"GDI32.dll", "USER32.dll", "msvcrt.dll", "api-ms-win-core-libraryloader-l1-2-0.dl"},
		VersionResources: map[string]string{"CompanyName": "Microsoft Corporation", "FileDescription": "Notepad", "FileVersion": "10.0.18362.693"},
	}
	ps := &PS{
		PID:       2436,
		Ppid:      6304,
		Name:      "firefox.exe",
		Exe:       `C:\Program Files\Mozilla Firefox\firefox.exe`,
		Cmdline:   `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`,
		Cwd:       `C:\Program Files\Mozilla Firefox\`,
		SID:       "archrabbit\\SYSTEM",
		Args:      []string{"-contentproc", `--channel="6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"},
		SessionID: 4,
		Envs:      map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
		uuid:      123456789,
		StartTime: n,
		PE:        p,
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
	}

	b := ps.Marshal()
	sec := section.New(section.Process, kcapver.ProcessSecV3, 0, 0)
	clone, err := NewFromKcap(b, sec)
	require.NoError(t, err)

	assert.Equal(t, uint32(2436), clone.PID)
	assert.Equal(t, uint32(6304), clone.Ppid)
	assert.Equal(t, "firefox.exe", clone.Name)
	assert.Equal(t, uint64(123456789), clone.uuid)
	assert.True(t, n.Equal(clone.StartTime))
	assert.Equal(t, `C:\Program Files\Mozilla Firefox\firefox.exe`, clone.Exe)
	assert.Equal(t, `C:\Program Files\Mozilla Firefox\firefox.exe -contentproc --channel="6304.3.1055809391\1014207667" -childID 1 -isForBrowser -prefsHandle 2584 -prefMapHandle 2580 -prefsLen 70 -prefMapSize 216993 -parentBuildID 20200107212822 -greomni "C:\Program Files\Mozilla Firefox\omni.ja" -appomni "C:\Program Files\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files\Mozilla Firefox\browser" - 6304 "\\.\pipe\gecko-crash-server-pipe.6304" 2596 tab`, clone.Cmdline)
	assert.Equal(t, `C:\Program Files\Mozilla Firefox\`, clone.Cwd)
	assert.Equal(t, "archrabbit\\SYSTEM", clone.SID)
	assert.Equal(t, []string{"-contentproc", `--channel="6304.3.1055809391\1014207667`, "-childID", "1", "-isForBrowser", "-prefsHandle", "2584", "-prefMapHandle", "2580", "-prefsLen", "70", "-prefMapSize", "216993", "-parentBuildID"}, clone.Args)
	assert.Equal(t, uint32(4), clone.SessionID)
	assert.Equal(t, map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"}, clone.Envs)

	require.Len(t, clone.Handles, 3)

	alpc := clone.Handles[1]
	assert.Equal(t, "ALPC Port", alpc.Type)
	assert.Equal(t, `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`, alpc.Name)
	assert.IsType(t, &htypes.AlpcPortInfo{}, alpc.MD)

	md := alpc.MD.(*htypes.AlpcPortInfo)
	assert.Equal(t, uint32(1), md.Seqno)
}
