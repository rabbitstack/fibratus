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
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/rabbitstack/fibratus/pkg/yara/config"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows/registry"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/event/params"
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
	log.SetLevel(log.DebugLevel)
	psnap := new(ps.SnapshotterMock)
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.Noop}}))

	var tests = []struct {
		name          string
		setup         func() (*event.Event, error)
		newScanner    func() (Scanner, error)
		expectedAlert alertsender.Alert
		matches       bool
	}{
		{
			"scan spawned process",
			func() (*event.Event, error) {
				var si windows.StartupInfo
				si.Flags = windows.STARTF_USESHOWWINDOW
				var pi windows.ProcessInformation

				argv := windows.StringToUTF16Ptr(filepath.Join(os.Getenv("windir"), "notepad.exe"))

				err := windows.CreateProcess(
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
				if err != nil {
					return nil, err
				}

				for {
					if sys.IsProcessRunning(pi.Process) {
						break
					}
					time.Sleep(time.Millisecond * 100)
					log.Infof("%d pid not yet ready", pi.Process)
				}

				proc := &pstypes.PS{
					Name:      "notepad.exe",
					PID:       11,
					Ppid:      2434,
					Exe:       `C:\Windows\notepad.exe`,
					Cmdline:   `C:\Windows\notepad.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\Windows\`,
					SessionID: 1,
				}
				psnap.On("Find", pi.ProcessId).Return(true, proc)

				e := &event.Event{
					Type: event.CreateProcess,
					Name: "CreateProcess",
					Tid:  2484,
					PID:  859,
					Params: event.Params{
						params.ProcessName: {Name: params.ProcessName, Type: params.UnicodeString, Value: "notepad.exe"},
						params.ProcessID:   {Name: params.ProcessID, Type: params.PID, Value: pi.ProcessId},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
				})
			},
			alertsender.Alert{
				Title: "Memory Threat Detected",
				Text:  "Threat detected Notepad.Shell",
				ID:    "babf9101-1e6e-4268-a530-e99e2c905b0d",
				Tags:  []string{"T1", "T2"},
			},
			true,
		},
		{
			"scan spawned process excluded by config",
			func() (*event.Event, error) {
				var si windows.StartupInfo
				si.Flags = windows.STARTF_USESHOWWINDOW
				si.ShowWindow = windows.SW_HIDE
				var pi windows.ProcessInformation

				argv := windows.StringToUTF16Ptr(filepath.Join(os.Getenv("windir"), "notepad.exe"))

				err := windows.CreateProcess(
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
				if err != nil {
					return nil, err
				}

				for {
					if sys.IsProcessRunning(pi.Process) {
						break
					}
					time.Sleep(time.Millisecond * 100)
					log.Infof("%d pid not yet ready", pi.Process)
				}

				proc := &pstypes.PS{
					Name:      "notepad.exe",
					PID:       11,
					Ppid:      2434,
					Exe:       `C:\Windows\notepad.exe`,
					Cmdline:   `C:\Windows\notepad.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\Windows\`,
					SessionID: 1,
				}
				psnap.On("Find", pi.ProcessId).Return(true, proc)

				e := &event.Event{
					Type: event.CreateProcess,
					Name: "CreateProcess",
					Tid:  2484,
					PID:  859,
					Params: event.Params{
						params.ProcessName: {Name: params.ProcessName, Type: params.UnicodeString, Value: "notepad.exe"},
						params.ProcessID:   {Name: params.ProcessID, Type: params.PID, Value: pi.ProcessId},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
					ExcludedProcesses: []string{"?:\\*\\notepad.exe"},
				})
			},
			alertsender.Alert{},
			false,
		},
		{
			"scan unsigned module loading",
			func() (*event.Event, error) {
				var si windows.StartupInfo
				si.Flags = windows.STARTF_USESHOWWINDOW
				var pi windows.ProcessInformation

				argv := windows.StringToUTF16Ptr(filepath.Join(os.Getenv("windir"), "regedit.exe"))

				err := windows.CreateProcess(
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
				if err != nil {
					return nil, err
				}

				for {
					if sys.IsProcessRunning(pi.Process) {
						break
					}
					time.Sleep(time.Millisecond * 100)
					log.Infof("%d pid not yet ready", pi.Process)
				}

				pid := pi.ProcessId
				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       pid,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", pid).Return(true, proc)

				e := &event.Event{
					Type: event.LoadImage,
					Name: "LoadImage",
					Tid:  2484,
					PID:  pid,
					Params: event.Params{
						params.FilePath:           {Name: params.FilePath, Type: params.UnicodeString, Value: "tests.exe"},
						params.ImageBase:          {Name: params.ImageBase, Type: params.Uint64, Value: uint64(0x74888fd99)},
						params.ImageSignatureType: {Name: params.ImageSignatureType, Type: params.Uint32, Value: signature.None},
						params.ProcessID:          {Name: params.ProcessID, Type: params.PID, Value: pid},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
				})
			},
			alertsender.Alert{
				Title: "Memory Threat Detected",
				Text:  "Threat detected Regedit",
				ID:    "1abf9101-1e6e-4268-a530-e99e2c905b0d",
				Tags:  []string{"T1"},
			},
			true,
		},
		{
			"scan pe file created in the file system",
			func() (*event.Event, error) {

				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       565,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", 565).Return(true, proc)

				e := &event.Event{
					Type:     event.CreateFile,
					Name:     "CreateFile",
					Category: event.File,
					Tid:      2484,
					PID:      565,
					Params: event.Params{
						params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: filepath.Join(os.Getenv("windir"), "notepad.exe")},
						params.FileOperation: {Name: params.FileOperation, Type: params.Uint32, Value: uint32(windows.FILE_CREATE)},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
				})
			},
			alertsender.Alert{
				Title: "File Threat Detected",
				Text:  "Threat detected Notepad.Shell",
				ID:    "babf9101-1e6e-4268-a530-e99e2c905b0d",
				Tags:  []string{"T1", "T2"},
			},
			true,
		},
		{
			"scan pe file excluded by config",
			func() (*event.Event, error) {

				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       565,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", 565).Return(true, proc)

				e := &event.Event{
					Type:     event.CreateFile,
					Name:     "CreateFile",
					Category: event.File,
					Tid:      2484,
					PID:      565,
					Params: event.Params{
						params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: filepath.Join(os.Getenv("windir"), "System32", "cmd.exe")},
						params.FileOperation: {Name: params.FileOperation, Type: params.Uint32, Value: uint32(windows.FILE_CREATE)},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
					ExcludedFiles: []string{
						`?:\WINDOWS\*\*.exe`,
					},
				})
			},
			alertsender.Alert{},
			false,
		},
		{
			"scan non-pe file created in the file system",
			func() (*event.Event, error) {

				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       565,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", 565).Return(true, proc)

				e := &event.Event{
					Type:     event.CreateFile,
					Name:     "CreateFile",
					Category: event.File,
					Tid:      2484,
					PID:      565,
					Params: event.Params{
						params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: filepath.Join(os.Getenv("windir"), "splwow64.xml")},
						params.FileOperation: {Name: params.FileOperation, Type: params.Uint32, Value: uint32(windows.FILE_CREATE)},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
				})
			},
			alertsender.Alert{},
			false,
		},
		{
			"scan pe file excluded by generating process name",
			func() (*event.Event, error) {

				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       565,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", 565).Return(true, proc)

				e := &event.Event{
					Type:     event.CreateFile,
					Name:     "CreateFile",
					Category: event.File,
					Tid:      2484,
					PID:      565,
					Params: event.Params{
						params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: filepath.Join(os.Getenv("windir"), "System32", "cmd.exe")},
						params.FileOperation: {Name: params.FileOperation, Type: params.Uint32, Value: uint32(windows.FILE_CREATE)},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
					ExcludedFiles: []string{
						`tests.exe`,
					},
				})
			},
			alertsender.Alert{},
			false,
		},
		{
			"scan ads created in the file system",
			func() (*event.Event, error) {
				ads := filepath.Join(os.TempDir(), "suspicious-ads.txt:mal")
				f, err := os.Create(ads)
				if err != nil {
					return nil, err
				}
				data := []byte{0x6F, 0x66, 0x74, 0x2E, 0x4E, 0x6F, 0x74, 0x65, 0x70, 0x61, 0x64, 0x00, 0x13, 0x00, 0x01, 0x1A}
				if err := os.WriteFile(ads, data, os.ModePerm); err != nil {
					return nil, err
				}
				defer f.Close()
				defer os.Remove(ads)

				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       565,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", 565).Return(true, proc)

				e := &event.Event{
					Type:     event.CreateFile,
					Name:     "CreateFile",
					Category: event.File,
					Tid:      2484,
					PID:      565,
					Params: event.Params{
						params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: ads},
						params.FileOperation: {Name: params.FileOperation, Type: params.Uint32, Value: uint32(windows.FILE_CREATE)},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
				})
			},
			alertsender.Alert{
				Title: "File Threat Detected",
				Text:  "Threat detected Notepad.Shell",
				ID:    "babf9101-1e6e-4268-a530-e99e2c905b0d",
				Tags:  []string{"T1", "T2"},
			},
			true,
		},
		{
			"scan rwx memory region allocation",
			func() (*event.Event, error) {
				var si windows.StartupInfo
				si.Flags = windows.STARTF_USESHOWWINDOW
				var pi windows.ProcessInformation

				argv := windows.StringToUTF16Ptr(filepath.Join(os.Getenv("windir"), "regedit.exe"))

				err := windows.CreateProcess(
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
				if err != nil {
					return nil, err
				}

				for {
					if sys.IsProcessRunning(pi.Process) {
						break
					}
					time.Sleep(time.Millisecond * 100)
					log.Infof("%d pid not yet ready", pi.Process)
				}

				pid := pi.ProcessId

				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       565,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", pid).Return(true, proc)

				e := &event.Event{
					Type:     event.VirtualAlloc,
					Name:     "VirtualAlloc",
					Category: event.Mem,
					Tid:      2484,
					PID:      565,
					Params: event.Params{
						params.ProcessID:      {Name: params.ProcessID, Type: params.PID, Value: pid},
						params.MemBaseAddress: {Name: params.MemBaseAddress, Type: params.Address, Value: uint64(0x7ffe0000)},
						params.MemProtect:     {Name: params.MemProtect, Type: params.Flags, Value: uint32(windows.PAGE_EXECUTE_READWRITE), Flags: event.MemProtectionFlags},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
				})
			},
			alertsender.Alert{
				Title: "Memory Threat Detected",
				Text:  "Threat detected Regedit",
				ID:    "1abf9101-1e6e-4268-a530-e99e2c905b0d",
				Tags:  []string{"T1"},
			},
			true,
		},
		{
			"scan rx pagefile mmap",
			func() (*event.Event, error) {
				var si windows.StartupInfo
				si.Flags = windows.STARTF_USESHOWWINDOW
				var pi windows.ProcessInformation

				argv := windows.StringToUTF16Ptr(filepath.Join(os.Getenv("windir"), "regedit.exe"))

				err := windows.CreateProcess(
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
				if err != nil {
					return nil, err
				}

				for {
					if sys.IsProcessRunning(pi.Process) {
						break
					}
					time.Sleep(time.Millisecond * 100)
					log.Infof("%d pid not yet ready", pi.Process)
				}

				pid := pi.ProcessId

				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       pid,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", pid).Return(true, proc)

				e := &event.Event{
					Type:     event.MapViewFile,
					Name:     "MapViewFile",
					Category: event.File,
					Tid:      2484,
					PID:      565,
					Params: event.Params{
						params.ProcessID:    {Name: params.ProcessID, Type: params.PID, Value: pid},
						params.FileViewBase: {Name: params.FileViewBase, Type: params.Address, Value: uint64(0x7ffe0000)},
						params.FileViewSize: {Name: params.FileViewSize, Type: params.Uint64, Value: uint64(12333)},
						params.MemProtect:   {Name: params.MemProtect, Type: params.Flags, Value: uint32(sys.SectionRX), Flags: event.ViewProtectionFlags},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
				})
			},
			alertsender.Alert{
				Title: "Memory Threat Detected",
				Text:  "Threat detected Regedit",
				ID:    "1abf9101-1e6e-4268-a530-e99e2c905b0d",
				Tags:  []string{"T1"},
			},
			true,
		},
		{
			"scan rx pagefile mmap address for signed module",
			func() (*event.Event, error) {
				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       1123,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", 1123).Return(true, proc)

				signature.GetSignatures().PutSignature(uint64(0x7f3e1000), &signature.Signature{Level: signature.AuthenticodeLevel, Type: signature.Catalog})

				e := &event.Event{
					Type:     event.MapViewFile,
					Name:     "MapViewFile",
					Category: event.File,
					Tid:      2484,
					PID:      565,
					Params: event.Params{
						params.ProcessID:    {Name: params.ProcessID, Type: params.PID, Value: uint32(1123)},
						params.FileViewBase: {Name: params.FileViewBase, Type: params.Address, Value: uint64(0x7f3e1000)},
						params.FileViewSize: {Name: params.FileViewSize, Type: params.Uint64, Value: uint64(12333)},
						params.MemProtect:   {Name: params.MemProtect, Type: params.Flags, Value: uint32(sys.SectionRX), Flags: event.ViewProtectionFlags},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
				})
			},
			alertsender.Alert{},
			false,
		},
		{
			"scan rx pagefile readonly mmap",
			func() (*event.Event, error) {
				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       321321,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", uint32(321321)).Return(true, proc)

				e := &event.Event{
					Type:     event.MapViewFile,
					Name:     "MapViewFile",
					Category: event.File,
					Tid:      2484,
					PID:      321321,
					Params: event.Params{
						params.ProcessID:    {Name: params.ProcessID, Type: params.PID, Value: uint32(321321)},
						params.FileViewBase: {Name: params.FileViewBase, Type: params.Address, Value: uint64(0x7ffe0000)},
						params.FileViewSize: {Name: params.FileViewSize, Type: params.Uint64, Value: uint64(12333)},
						params.MemProtect:   {Name: params.MemProtect, Type: params.Flags, Value: uint32(0x10000), Flags: event.ViewProtectionFlags},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
				})
			},
			alertsender.Alert{},
			false,
		},
		{
			"scan rwx image file mmap",
			func() (*event.Event, error) {
				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       1123,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", 1123).Return(true, proc)

				e := &event.Event{
					Type:     event.MapViewFile,
					Name:     "MapViewFile",
					Category: event.File,
					Tid:      2484,
					PID:      565,
					Params: event.Params{
						params.ProcessID:    {Name: params.ProcessID, Type: params.PID, Value: uint32(1123)},
						params.FilePath:     {Name: params.FilePath, Type: params.UnicodeString, Value: filepath.Join(os.Getenv("windir"), "regedit.exe")},
						params.FileViewBase: {Name: params.FileViewBase, Type: params.Address, Value: uint64(0x7ffe0000)},
						params.FileViewSize: {Name: params.FileViewSize, Type: params.Uint64, Value: uint64(12333)},
						params.MemProtect:   {Name: params.MemProtect, Type: params.Flags, Value: uint32(sys.SectionRWX), Flags: event.ViewProtectionFlags},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
				})
			},
			alertsender.Alert{
				Title: "File Threat Detected",
				Text:  "Threat detected Regedit",
				ID:    "1abf9101-1e6e-4268-a530-e99e2c905b0d",
				Tags:  []string{"T1"},
			},
			true,
		},
		{
			"scan registry binary value",
			func() (*event.Event, error) {
				proc := &pstypes.PS{
					Name:      "tests.exe",
					PID:       1123,
					Ppid:      uint32(os.Getppid()),
					Exe:       `C:\ProgramData\tests.exe`,
					Cmdline:   `C:\ProgramData\tests.exe`,
					SID:       "S-1-1-18",
					Cwd:       `C:\ProgramData\`,
					SessionID: 1,
				}
				psnap.On("Find", 1123).Return(true, proc)

				data := []byte{0x6F, 0x66, 0x74, 0x2E, 0x4E, 0x6F, 0x74, 0x65, 0x70, 0x61, 0x64, 0x00, 0x13, 0x00, 0x01, 0x1A}
				e := &event.Event{
					Type:     event.RegSetValue,
					Name:     "RegSetValue",
					Category: event.Registry,
					Tid:      2484,
					PID:      565,
					Params: event.Params{
						params.RegValueType: {Name: params.RegValueType, Type: params.Uint32, Value: uint32(registry.BINARY)},
						params.RegValue:     {Name: params.RegValue, Type: params.Binary, Value: data},
						params.RegPath:      {Name: params.RegPath, Type: params.UnicodeString, Value: `HKEY_LOCAL_MACHINE\CurrentControlSet\Control\DeviceGuard\Mal`},
					},
					Metadata: make(map[event.MetadataKey]any),
					PS:       proc,
				}
				return e, nil
			},
			func() (Scanner, error) {
				return NewScanner(psnap, config.Config{
					Enabled:     true,
					ScanTimeout: time.Minute,
					Rule: config.Rule{
						Paths: []config.RulePath{
							{
								Namespace: "default",
								Path:      "_fixtures/rules",
							},
						},
					},
				})
			},
			alertsender.Alert{
				Title: "File Threat Detected",
				Text:  "Threat detected Notepad.Shell",
				ID:    "babf9101-1e6e-4268-a530-e99e2c905b0d",
				Tags:  []string{"T1", "T2"},
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := tt.setup()
			require.NoError(t, err)

			// initialize scanner
			s, err := tt.newScanner()
			require.NoError(t, err)
			defer s.Close()

			matches, err := s.Scan(e)
			require.NoError(t, err)
			require.Equal(t, matches, tt.matches)

			if matches {
				// compare alert content
				require.NotNil(t, yaraAlert)
				assert.Equal(t, tt.expectedAlert.Title, yaraAlert.Title)
				assert.Equal(t, tt.expectedAlert.Text, yaraAlert.Text)
				assert.Equal(t, tt.expectedAlert.ID, yaraAlert.ID)
				assert.Equal(t, tt.expectedAlert.Tags, yaraAlert.Tags)
				assert.True(t, len(yaraAlert.Labels) > 0)
				assert.Len(t, yaraAlert.Events, 1)
				assert.NotEmpty(t, e.Metadata)
				assert.Contains(t, e.Metadata, event.YaraMatchesKey)
			}

			if e.IsCreateProcess() || e.IsLoadImage() || e.IsVirtualAlloc() || e.IsMapViewFile() {
				// cleanup
				proc, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, e.Params.MustGetPid())
				if err == nil {
					windows.TerminateProcess(proc, uint32(257))
					windows.Close(proc)
				}
			}
		})
	}
}
