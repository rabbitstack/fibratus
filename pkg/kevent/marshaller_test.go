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

package kevent

import (
	"encoding/json"
	kcapver "github.com/rabbitstack/fibratus/pkg/kcap/version"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"os"
	"testing"
	"time"

	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	pex "github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	SerializeThreads = true
	SerializeImages = true
	SerializeHandles = true
	SerializePE = true
	SerializeEnvs = true
}

func TestMarshaller(t *testing.T) {
	now, err := time.Parse(time.RFC3339Nano, time.Now().Format(time.RFC3339Nano))
	require.NoError(t, err)

	kevt := &Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   now,
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
			kparams.BasePrio:      {Name: kparams.BasePrio, Type: kparams.Int8, Value: int8(2)},
			kparams.PagePrio:      {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(2)},
			kparams.KstackLimit:   {Name: kparams.KstackLimit, Type: kparams.Address, Value: uint64(1888833888)},
			kparams.StartTime:     {Name: kparams.StartTime, Type: kparams.Time, Value: time.Now()},
			kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1204)},
			kparams.NetDIPNames:   {Name: kparams.NetDIPNames, Type: kparams.Slice, Value: []string{"dns.google.", "github.com."}},
		},
		Metadata: map[MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	b := kevt.MarshalRaw()
	require.NotEmpty(t, b)

	clone, err := NewFromKcap(b, kcapver.KevtSecV2)
	require.NoError(t, err)

	assert.Equal(t, uint64(2), clone.Seq)
	assert.Equal(t, uint32(859), clone.PID)
	assert.Equal(t, uint32(2484), clone.Tid)
	assert.Equal(t, ktypes.CreateFile, clone.Type)
	assert.Equal(t, uint8(1), clone.CPU)
	assert.Equal(t, "CreateFile", clone.Name)
	assert.Equal(t, ktypes.File, clone.Category)
	assert.Equal(t, "Creates or opens a new file, directory, I/O device, pipe, console", clone.Description)
	assert.Equal(t, "archrabbit", clone.Host)
	assert.Equal(t, now, clone.Timestamp)

	assert.Len(t, clone.Kparams, 10)

	filename, err := clone.Kparams.GetString(kparams.FileName)
	require.NoError(t, err)
	assert.Equal(t, "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll", filename)
	fileobject, err := clone.Kparams.GetUint64(kparams.FileObject)
	require.NoError(t, err)
	assert.Equal(t, uint64(12456738026482168384), fileobject)

	assert.Len(t, clone.Metadata, 2)

	assert.Equal(t, "bar", clone.Metadata["foo"])
	assert.Equal(t, "barzz", clone.Metadata["fooz"])
}

func TestKeventMarshalJSON(t *testing.T) {
	kevt := &Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
			kparams.BasePrio:      {Name: kparams.BasePrio, Type: kparams.Int8, Value: int8(2)},
			kparams.PagePrio:      {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(2)},
			kparams.NetDIPNames:   {Name: kparams.NetDIPNames, Type: kparams.Slice, Value: []string{"dns.google.", "github.com."}},
		},
		Metadata: map[MetadataKey]any{"foo": "bar", "fooz": "baarz"},
		PS: &pstypes.PS{
			PID:  2436,
			Ppid: 6304,
			Parent: &pstypes.PS{
				Name: "explorer.exe",
				Exe:  `C:\Windows\System32\explorer.exe`,
				Cwd:  `C:\Windows\System32`,
				SID:  "admin\\SYSTEM",
			},
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
			PE: &pex.PE{
				NumberOfSections: 2,
				NumberOfSymbols:  10,
				EntryPoint:       "0x20110",
				ImageBase:        "0x140000000",
				LinkTime:         time.Now(),
				Sections: []pex.Sec{
					{Name: ".text", Size: 132608, Entropy: 6.368381, Md5: "db23dce3911a42e987041d98abd4f7cd"},
					{Name: ".rdata", Size: 35840, Entropy: 5.996976, Md5: "ffa5c960b421ca9887e54966588e97e8"},
				},
				Symbols:          []string{"SelectObject", "GetTextFaceW", "EnumFontsW", "TextOutW", "GetProcessHeap"},
				Imports:          []string{"GDI32.dll", "USER32.dll", "msvcrt.dll", "api-ms-win-core-libraryloader-l1-2-0.dl"},
				VersionResources: map[string]string{"CompanyName": "Microsoft Corporation", "FileDescription": "Notepad", "FileVersion": "10.0.18362.693"},
			},
		},
	}
	s := kevt.MarshalJSON()
	var newKevt Kevent
	err := json.Unmarshal(s, &newKevt)
	require.NoError(t, err)

	assert.Equal(t, uint32(2484), newKevt.Tid)
	assert.Equal(t, uint32(859), newKevt.PID)
	assert.Equal(t, "archrabbit\\SYSTEM", newKevt.PS.SID)
	assert.Len(t, newKevt.PS.Envs, 2)
	assert.Len(t, newKevt.PS.Handles, 3)

	assert.NotNil(t, newKevt.PS.PE)
	assert.Equal(t, "explorer.exe", newKevt.PS.Parent.Name)
	assert.Equal(t, uint32(10), newKevt.PS.PE.NumberOfSymbols)
	assert.Equal(t, uint16(2), newKevt.PS.PE.NumberOfSections)
	assert.Len(t, newKevt.PS.PE.Sections, 2)
	assert.Len(t, newKevt.PS.PE.Symbols, 5)
	assert.Len(t, newKevt.PS.PE.Imports, 4)
	assert.Len(t, newKevt.PS.PE.VersionResources, 3)
}

func TestUnmarshalHugeHandles(t *testing.T) {
	b, err := os.ReadFile("_fixtures\\handles.json")
	require.NoError(t, err)
	handles := make([]htypes.Handle, 0)
	err = json.Unmarshal(b, &handles)
	require.NoError(t, err)

	kevt := &Kevent{
		Type:        ktypes.CreateProcess,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateProcess",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates a new process",
		Kparams: Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
			kparams.BasePrio:      {Name: kparams.BasePrio, Type: kparams.Int8, Value: int8(2)},
			kparams.PagePrio:      {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(2)},
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
			Handles: handles,
			PE: &pex.PE{
				NumberOfSections: 7,
				NumberOfSymbols:  10,
				EntryPoint:       "0x20110",
				ImageBase:        "0x140000000",
				LinkTime:         time.Now(),
				Sections: []pex.Sec{
					{Name: ".text", Size: 132608, Entropy: 6.368381, Md5: "db23dce3911a42e987041d98abd4f7cd"},
					{Name: ".rdata", Size: 35840, Entropy: 5.996976, Md5: "ffa5c960b421ca9887e54966588e97e8"},
				},
				Symbols:          []string{"SelectObject", "GetTextFaceW", "EnumFontsW", "TextOutW", "GetProcessHeap"},
				Imports:          []string{"GDI32.dll", "USER32.dll", "msvcrt.dll", "api-ms-win-core-libraryloader-l1-2-0.dl"},
				VersionResources: map[string]string{"CompanyName": "Microsoft Corporation", "FileDescription": "Notepad", "FileVersion": "10.0.18362.693"},
			},
		},
	}

	s := kevt.MarshalRaw()
	clone, err := NewFromKcap(s, kcapver.KevtSecV2)
	require.NoError(t, err)
	require.NotNil(t, clone)
}

func TestKeventMarshalJSONMultiple(t *testing.T) {
	for i := 0; i < 10; i++ {
		seq := uint64(i + 1)
		kevt := &Kevent{
			Type:        ktypes.CreateFile,
			Tid:         2484,
			PID:         859,
			CPU:         1,
			Seq:         seq,
			Name:        "CreateFile",
			Timestamp:   time.Now(),
			Category:    ktypes.File,
			Host:        "archrabbit",
			Description: "Creates or opens a new file, directory, I/O device, pipe, console",
			Kparams: Kparams{
				kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
				kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
				kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
				kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
				kparams.BasePrio:      {Name: kparams.BasePrio, Type: kparams.Int8, Value: int8(2)},
				kparams.PagePrio:      {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(2)},
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
		s := kevt.MarshalJSON()
		var newKevt Kevent
		err := json.Unmarshal(s, &newKevt)
		require.NoError(t, err)

		assert.Equal(t, uint32(2484), newKevt.Tid)
		assert.Equal(t, uint32(859), newKevt.PID)
		assert.Equal(t, seq, newKevt.Seq)
		assert.Len(t, newKevt.PS.Handles, 3)
	}
}

func BenchmarkKeventMarshalJSON(b *testing.B) {
	kevt := &Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
			kparams.BasePrio:      {Name: kparams.BasePrio, Type: kparams.Int8, Value: int8(2)},
			kparams.PagePrio:      {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(2)},
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
			PE: &pex.PE{
				NumberOfSections: 2,
				NumberOfSymbols:  10,
				EntryPoint:       "0x20110",
				ImageBase:        "0x140000000",
				LinkTime:         time.Now(),
				Sections: []pex.Sec{
					{Name: ".text", Size: 132608, Entropy: 6.368381, Md5: "db23dce3911a42e987041d98abd4f7cd"},
					{Name: ".rdata", Size: 35840, Entropy: 5.996976, Md5: "ffa5c960b421ca9887e54966588e97e8"},
				},
				Symbols:          []string{"SelectObject", "GetTextFaceW", "EnumFontsW", "TextOutW", "GetProcessHeap"},
				Imports:          []string{"GDI32.dll", "USER32.dll", "msvcrt.dll", "api-ms-win-core-libraryloader-l1-2-0.dl"},
				VersionResources: map[string]string{"CompanyName": "Microsoft Corporation", "FileDescription": "Notepad", "FileVersion": "10.0.18362.693"},
			},
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		kevt.MarshalJSON()
	}
}

func BenchmarkKeventMarshalJSONStdlib(b *testing.B) {
	kevt := &Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
			kparams.BasePrio:      {Name: kparams.BasePrio, Type: kparams.Int8, Value: int8(2)},
			kparams.PagePrio:      {Name: kparams.PagePrio, Type: kparams.Uint8, Value: uint8(2)},
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
			PE: &pex.PE{
				NumberOfSections: 2,
				NumberOfSymbols:  10,
				EntryPoint:       "0x20110",
				ImageBase:        "0x140000000",
				LinkTime:         time.Now(),
				Sections: []pex.Sec{
					{Name: ".text", Size: 132608, Entropy: 6.368381, Md5: "db23dce3911a42e987041d98abd4f7cd"},
					{Name: ".rdata", Size: 35840, Entropy: 5.996976, Md5: "ffa5c960b421ca9887e54966588e97e8"},
				},
				Symbols:          []string{"SelectObject", "GetTextFaceW", "EnumFontsW", "TextOutW", "GetProcessHeap"},
				Imports:          []string{"GDI32.dll", "USER32.dll", "msvcrt.dll", "api-ms-win-core-libraryloader-l1-2-0.dl"},
				VersionResources: map[string]string{"CompanyName": "Microsoft Corporation", "FileDescription": "Notepad", "FileVersion": "10.0.18362.693"},
			},
		},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(kevt); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMarshal(b *testing.B) {
	kevt := &Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
		},
		Metadata: map[MetadataKey]any{"foo": "bar", "fooz": "barz"},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if buf := kevt.MarshalRaw(); len(buf) == 0 {
			b.Fatal("empty buffer")
		}
	}
}

func BenchmarkUnmarshal(b *testing.B) {
	kevt := &Kevent{
		Type:        ktypes.CreateFile,
		Tid:         2484,
		PID:         859,
		CPU:         1,
		Seq:         2,
		Name:        "CreateFile",
		Timestamp:   time.Now(),
		Category:    ktypes.File,
		Host:        "archrabbit",
		Description: "Creates or opens a new file, directory, I/O device, pipe, console",
		Kparams: Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12456738026482168384)},
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileType:      {Name: kparams.FileType, Type: kparams.AnsiString, Value: "file"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.AnsiString, Value: "open"},
		},
		Metadata: map[MetadataKey]any{"foo": "bar", "fooz": "barz"},
	}
	buf := kevt.MarshalRaw()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ke, err := NewFromKcap(buf, kcapver.KevtSecV2)
		if err != nil {
			b.Fatal(err)
		}
		if ke.Name == "" {
			b.Fatal("invalid unmarshal byte slice")
		}
	}
}
