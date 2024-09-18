//go:build yara
// +build yara

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

package yara

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hillu/go-yara/v4"
	log "github.com/sirupsen/logrus"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/rabbitstack/fibratus/pkg/yara/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/windows"
)

var yaraAlert *alertsender.Alert

type mockSender struct{}

func (s *mockSender) Send(a alertsender.Alert) error {
	yaraAlert = &a
	return nil
}

func (s *mockSender) Type() alertsender.Type {
	return alertsender.Noop
}

func (s *mockSender) Shutdown() error        { return nil }
func (s *mockSender) SupportsMarkdown() bool { return true }

func makeSender(config alertsender.Config) (alertsender.Sender, error) {
	return &mockSender{}, nil
}

func init() {
	alertsender.Register(alertsender.Noop, makeSender)
}

func TestScan(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.Noop}}))

	s, err := NewScanner(psnap, config.Config{
		Enabled:     true,
		ScanTimeout: time.Minute,
		AlertVia:    "noop",
		Rule: config.Rule{
			Paths: []config.RulePath{
				{
					Namespace: "default",
					Path:      "_fixtures/rules",
				},
			},
		},
	})
	require.NoError(t, err)

	var si windows.StartupInfo
	si.Flags = windows.STARTF_USESHOWWINDOW
	si.ShowWindow = windows.SW_HIDE
	var pi windows.ProcessInformation

	argv := windows.StringToUTF16Ptr(filepath.Join(os.Getenv("windir"), "notepad.exe"))

	err = windows.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		true,
		0,
		nil,
		nil,
		&si,
		&pi)
	require.NoError(t, err)
	//nolint:errcheck
	defer windows.TerminateProcess(pi.Process, uint32(257))

	proc := &pstypes.PS{
		Name:      "notepad.exe",
		PID:       pi.ProcessId,
		Ppid:      2434,
		Exe:       `C:\Windows\notepad.exe`,
		Cmdline:   `C:\Windows\notepad.exe`,
		SID:       "S-1-1-18",
		Cwd:       `C:\Windows\`,
		SessionID: 1,
		Threads: map[uint32]pstypes.Thread{
			3453: {Tid: 3453, StartAddress: va.Address(140729524944768), IOPrio: 2, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
			3455: {Tid: 3455, StartAddress: va.Address(140729524944768), IOPrio: 3, PagePrio: 5, KstackBase: va.Address(18446677035730165760), KstackLimit: va.Address(18446677035730137088), UstackLimit: va.Address(86376448), UstackBase: va.Address(86372352)},
		},
		Envs: map[string]string{"ProgramData": "C:\\ProgramData", "COMPUTRENAME": "archrabbit"},
		Modules: []pstypes.Module{
			{Name: "kernel32.dll", Size: 12354, Checksum: 23123343, BaseAddress: va.Address(4294066175), DefaultBaseAddress: va.Address(4293993725)},
			{Name: "user32.dll", Size: 212354, Checksum: 33123343, BaseAddress: va.Address(4277288959), DefaultBaseAddress: va.Address(4293993725)},
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
		PE: &pe.PE{
			NumberOfSections: 2,
			NumberOfSymbols:  10,
			EntryPoint:       "0x20110",
			ImageBase:        "0x140000000",
			LinkTime:         time.Now(),
			Sections: []pe.Sec{
				{Name: ".text", Size: 132608, Entropy: 6.368381, Md5: "db23dce3911a42e987041d98abd4f7cd"},
				{Name: ".rdata", Size: 35840, Entropy: 5.996976, Md5: "ffa5c960b421ca9887e54966588e97e8"},
			},
			Symbols:          []string{"SelectObject", "GetTextFaceW", "EnumFontsW", "TextOutW", "GetProcessHeap"},
			Imports:          []string{"GDI32.dll", "USER32.dll", "msvcrt.dll", "api-ms-win-core-libraryloader-l1-2-0.dl"},
			VersionResources: map[string]string{"CompanyName": "Microsoft Corporation", "FileDescription": "Notepad", "FileVersion": "10.0.18362.693"},
		},
	}
	psnap.On("Find", mock.Anything).Return(true, proc)

	for {
		if sys.IsProcessRunning(pi.Process) {
			break
		}
		time.Sleep(time.Millisecond * 100)
		log.Infof("%d pid not yet ready", pi.Process)
	}

	kevt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Name: "CreateProcess",
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "svchost.exe"},
			kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: pi.ProcessId},
		},
		Metadata: make(map[kevent.MetadataKey]any),
	}

	// test attaching on pid
	match, err := s.Scan(kevt)
	require.NoError(t, err)
	require.True(t, match)
	require.NotNil(t, yaraAlert)

	assert.Equal(t, "YARA alert on process notepad.exe", yaraAlert.Title)
	assert.NotEmpty(t, yaraAlert.Text)
	assert.Contains(t, yaraAlert.Tags, "notepad")

	// test file scanning on DLL that merely contains
	// the fmt.Println("Go Yara DLL Test") statement
	kevt1 := &kevent.Kevent{
		Type: ktypes.LoadImage,
		Name: "LoadImage",
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.ImageFilename: {Name: kparams.ImageFilename, Type: kparams.UnicodeString, Value: "_fixtures/yara-test.dll"},
			kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.PID, Value: pi.ProcessId},
		},
		Metadata: make(map[kevent.MetadataKey]any),
	}
	match, err = s.Scan(kevt1)
	require.NoError(t, err)
	require.True(t, match)
	require.NotNil(t, yaraAlert)

	assert.Equal(t, "YARA alert on file _fixtures/yara-test.dll", yaraAlert.Title)
	assert.Contains(t, yaraAlert.Tags, "dll")

	// test file scanning notepad.exe triggered by a VirtualAlloc
	// event with RWX protection flags.
	kevt2 := &kevent.Kevent{
		Type: ktypes.VirtualAlloc,
		Name: "VirtualAlloc",
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "svchost.exe"},
			kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: pi.ProcessId},
			kparams.MemProtect:  {Name: kparams.MemProtect, Type: kparams.Flags, Value: uint32(windows.PAGE_EXECUTE_READWRITE), Flags: kevent.MemProtectionFlags},
		},
		Metadata: make(map[kevent.MetadataKey]any),
	}
	match, err = s.Scan(kevt2)
	require.NoError(t, err)
	require.True(t, match)
	require.NotNil(t, yaraAlert)

	assert.Equal(t, "YARA alert on process notepad.exe", yaraAlert.Title)
	assert.NotEmpty(t, yaraAlert.Text)
	assert.Contains(t, yaraAlert.Tags, "notepad")

}

func TestMatchesMeta(t *testing.T) {
	yaraMatches := []yara.MatchRule{
		{Rule: "test", Namespace: "ns1"},
		{Rule: "test2", Namespace: "ns2", Tags: []string{"dropper"}, Metas: []yara.Meta{{Identifier: "author", Value: "rabbit"}}},
	}

	kevt := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Name: "CreateProcess",
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "svchost.exe"},
		},
		Metadata: make(map[kevent.MetadataKey]any),
	}
	assert.Empty(t, kevt.Metadata)

	putMatchesMeta(yaraMatches, kevt)

	assert.NotEmpty(t, kevt.Metadata)
	assert.Contains(t, kevt.Metadata, kevent.YaraMatchesKey)
}
