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
package kstream

import (
	"context"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"
)

// MockListener receives the event and does nothing but indicating the event was processed.
type MockListener struct {
	gotEvent bool
}

func (l *MockListener) ProcessEvent(e *kevent.Kevent) (bool, error) {
	l.gotEvent = true
	return true, nil
}

func TestRundownEvents(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	psnap.On("Write", mock.Anything).Return(nil)
	psnap.On("AddThread", mock.Anything).Return(nil)
	psnap.On("AddModule", mock.Anything).Return(nil)
	psnap.On("RemoveThread", mock.Anything, mock.Anything).Return(nil)
	psnap.On("RemoveModule", mock.Anything, mock.Anything).Return(nil)
	psnap.On("FindAndPut", mock.Anything).Return(&pstypes.PS{})
	psnap.On("Find", mock.Anything).Return(true, &pstypes.PS{})
	psnap.On("Remove", mock.Anything).Return(nil)

	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindByObject", mock.Anything).Return(htypes.Handle{}, false)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)

	kstreamConfig := config.KstreamConfig{
		EnableThreadKevents:   true,
		EnableImageKevents:    true,
		EnableFileIOKevents:   true,
		EnableNetKevents:      true,
		EnableRegistryKevents: true,
	}

	kctrl := NewController(kstreamConfig)
	require.NoError(t, kctrl.Start())
	defer kctrl.Close()
	kstreamc := NewConsumer(psnap, hsnap, &config.Config{
		Kstream:  kstreamConfig,
		KcapFile: "fake.kcap", // simulate capture to receive state/rundown events
		Filters:  &config.Filters{},
	})
	l := &MockListener{}
	kstreamc.RegisterEventListener(l)
	require.NoError(t, kstreamc.Open())
	defer kstreamc.Close()

	rundownsByType := map[ktypes.Ktype]bool{
		ktypes.ProcessRundown: false,
		ktypes.ThreadRundown:  false,
		ktypes.ImageRundown:   false,
		ktypes.FileRundown:    false,
		ktypes.RegKCBRundown:  false,
	}
	rundownsByHash := make(map[uint64]uint8)
	timeout := time.After(time.Second * 10)

	for {
		select {
		case e := <-kstreamc.Events():
			if !e.IsRundown() {
				continue
			}
			rundownsByType[e.Type] = true
			rundownsByHash[e.RundownKey()]++
		case err := <-kstreamc.Errors():
			t.Fatalf("FAIL: %v", err)
		case <-timeout:
			t.Logf("got %d rundown events", len(rundownsByHash))
			for key, count := range rundownsByHash {
				if count > 1 {
					t.Fatalf("got more than 1 rundown event for key %d", key)
				}
			}
			for typ, got := range rundownsByType {
				if !got {
					t.Fatalf("no rundown events for %s", typ.String())
				}
			}
			return
		}
	}
}

func TestConsumerEvents(t *testing.T) {
	kevent.DropCurrentProc = false
	var viewBase uintptr
	var tests = []*struct {
		name      string
		gen       func() error
		want      func(e *kevent.Kevent) bool
		completed bool
	}{
		{
			"spawn new process",
			func() error {
				var si windows.StartupInfo
				var pi windows.ProcessInformation
				argv, err := windows.UTF16PtrFromString(filepath.Join(os.Getenv("windir"), "notepad.exe"))
				if err != nil {
					return err
				}
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
				if err != nil {
					return err
				}
				defer windows.TerminateProcess(pi.Process, 0)
				return nil
			},
			func(e *kevent.Kevent) bool {
				return e.IsCreateProcess() && e.CurrentPid() &&
					strings.EqualFold(e.GetParamAsString(kparams.ProcessName), "notepad.exe")
			},
			false,
		},
		{
			"terminate process",
			nil,
			func(e *kevent.Kevent) bool {
				return e.IsTerminateProcess() && strings.EqualFold(e.GetParamAsString(kparams.ProcessName), "notepad.exe")
			},
			false,
		},
		{
			"load image",
			nil,
			func(e *kevent.Kevent) bool {
				img := filepath.Join(os.Getenv("windir"), "System32", "notepad.exe")
				// should get a catalog-signed binary
				signatureType := e.GetParamAsString(kparams.ImageSignatureType)
				return e.IsLoadImage() && strings.EqualFold(img, e.GetParamAsString(kparams.ImageFilename)) &&
					signatureType == "CATALOG_CACHED"
			},
			false,
		},
		{
			"create new file",
			func() error {
				f, err := os.CreateTemp(os.TempDir(), "fibratus-test")
				if err != nil {
					return err
				}
				defer f.Close()
				return nil
			},
			func(e *kevent.Kevent) bool {
				return e.CurrentPid() && e.Type == ktypes.CreateFile &&
					strings.HasPrefix(filepath.Base(e.GetParamAsString(kparams.FileName)), "fibratus-test") &&
					e.GetParamAsString(kparams.FileOperation) != "OPEN"
			},
			false,
		},
		{
			"connect socket",
			func() error {
				go func() {
					srv := http.Server{
						Addr: ":18090",
					}
					mux := http.NewServeMux()
					mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {})
					time.AfterFunc(time.Second*2, func() {
						//nolint:noctx
						resp, _ := http.Get("http://localhost:18090")
						if resp != nil {
							defer func() {
								_ = resp.Body.Close()
							}()
						}
						_ = srv.Shutdown(context.TODO())
					})
					_ = srv.ListenAndServe()
				}()
				return nil
			},
			func(e *kevent.Kevent) bool {
				return e.CurrentPid() && (e.Type == ktypes.ConnectTCPv4 || e.Type == ktypes.ConnectTCPv6)
			},
			false,
		},
		{
			"unmap view section",
			func() error {
				sec, err := createSection()
				if err != nil {
					return nil
				}
				defer windows.Close(windows.Handle(sec))
				viewBase, err = NtMapViewOfSection(windows.Handle(sec), windows.CurrentProcess(), 1024, windows.SUB_CONTAINERS_ONLY_INHERIT, windows.PAGE_READONLY)
				if err != nil {
					return err
				}
				return NtUnmapViewSection(windows.CurrentProcess(), viewBase)
			},
			func(e *kevent.Kevent) bool {
				if e.CurrentPid() && e.Type == ktypes.MapViewFile && e.Kparams.MustGetUint64(kparams.FileViewBase) == uint64(viewBase) {
					fmt.Println(e)
				}
				return e.CurrentPid() && e.Type == ktypes.UnmapViewFile && e.Kparams.MustGetUint64(kparams.FileViewBase) == uint64(viewBase)
			},
			false,
		},
	}

	psnap := new(ps.SnapshotterMock)
	psnap.On("Write", mock.Anything).Return(nil)
	psnap.On("AddThread", mock.Anything).Return(nil)
	psnap.On("AddModule", mock.Anything).Return(nil)
	psnap.On("RemoveThread", mock.Anything, mock.Anything).Return(nil)
	psnap.On("RemoveModule", mock.Anything, mock.Anything).Return(nil)
	psnap.On("FindAndPut", mock.Anything).Return(&pstypes.PS{})
	psnap.On("Find", mock.Anything).Return(true, &pstypes.PS{})
	psnap.On("Remove", mock.Anything).Return(nil)

	hsnap := new(handle.SnapshotterMock)
	hsnap.On("FindByObject", mock.Anything).Return(htypes.Handle{}, false)
	hsnap.On("FindHandles", mock.Anything).Return([]htypes.Handle{}, nil)
	hsnap.On("Write", mock.Anything).Return(nil)
	hsnap.On("Remove", mock.Anything).Return(nil)

	kstreamConfig := config.KstreamConfig{
		EnableThreadKevents:   true,
		EnableImageKevents:    true,
		EnableFileIOKevents:   true,
		EnableNetKevents:      true,
		EnableRegistryKevents: true,
	}

	kctrl := NewController(kstreamConfig)
	require.NoError(t, kctrl.Start())
	defer kctrl.Close()
	kstreamc := NewConsumer(psnap, hsnap, &config.Config{Kstream: kstreamConfig, Filters: &config.Filters{}})
	l := &MockListener{}
	kstreamc.RegisterEventListener(l)
	require.NoError(t, kstreamc.Open())
	defer kstreamc.Close()

	time.Sleep(time.Second * 2)

	for _, tt := range tests {
		gen := tt.gen
		if gen != nil {
			require.NoError(t, gen())
		}
	}

	ntests := len(tests)
	timeout := time.After(time.Duration(ntests) * time.Minute)

	for {
		select {
		case e := <-kstreamc.Events():
			for _, tt := range tests {
				if tt.completed {
					continue
				}
				pred := tt.want
				if pred(e) {
					t.Logf("PASS: %s", tt.name)
					tt.completed = true
					ntests--
				}
				if ntests == 0 {
					assert.True(t, l.gotEvent)
					return
				}
			}
		case err := <-kstreamc.Errors():
			t.Fatalf("FAIL: %v", err)
		case <-timeout:
			for _, tt := range tests {
				if !tt.completed {
					t.Logf("FAIL: %s", tt.name)
				}
			}
			t.Fatal("FAIL: TestConsumerEvents")
		}
	}
}

const SEC_IMAGE = 0x01000000
const SEC_COMMIT = 0x8000000
const SEC_RESERVE = 0x04000000
const SEC_NOCACHE = 0x10000000
const SECTION_WRITE = 0x2
const SECTION_READ = 0x4
const SECTION_EXECUTE = 0x8
const SECTION_RWX = SECTION_WRITE | SECTION_READ | SECTION_EXECUTE

var flags uint64 = 0xC3000000000000

var r = uint32(0x10000)
var x = uint32(0x20000)
var rx = uint32(0x30000)
var rw = uint32(0x40000)

//10000010000000000000000
//00000010000000000000000

func TestBitmasks(t *testing.T) {
	f := uint32(flags >> 32)
	fmt.Printf("%b\n %x\n", f, (f >> 20))
	//if (flags & 1 << 31) != 0 {
	//	fmt.Println("K")
	//}
	//fmt.Println(byte(flags>>28) & 0xF)
}

func createSection() (uintptr, error) {
	var e error
	var err uintptr
	var ntdll *windows.LazyDLL
	var section uintptr

	// Load DLL
	ntdll = windows.NewLazySystemDLL("ntdll")

	f, err1 := os.Open("C:\\Users\\nedo\\Desktop\\fibratus-todo.txt")
	if err1 != nil {
		return 0, err1
	}
	fs, _ := f.Stat()
	size := int64(fs.Size())
	err, _, e = ntdll.NewProc("NtCreateSection").Call(
		uintptr(unsafe.Pointer(&section)),
		SECTION_READ|windows.STANDARD_RIGHTS_REQUIRED,
		0,
		uintptr(unsafe.Pointer(&size)),
		windows.PAGE_READONLY,
		SEC_RESERVE,
		f.Fd(),
	)
	if err != 0 {
		return section, fmt.Errorf("%0x: %s", uint32(err), e.Error())
	} else if section == 0 {
		return section, fmt.Errorf("NtCreateSection failed for unknown reason")
	}
	fmt.Printf("%0x\n", section)

	return section, nil
}

func NtMapViewOfSection(
	sHndl windows.Handle,
	pHndl windows.Handle,
	size uint64,
	inheritPerms uintptr,
	pagePerms uintptr,
) (uintptr, error) {
	var err uintptr
	var proc string = "NtMapViewOfSection"
	var scBase uintptr
	var scOffset uintptr
	var ntdll *windows.LazyDLL

	ntdll = windows.NewLazySystemDLL("ntdll")
	err, _, _ = ntdll.NewProc(proc).Call(
		uintptr(sHndl),
		uintptr(pHndl),
		uintptr(unsafe.Pointer(&scBase)),
		0,
		0,
		uintptr(unsafe.Pointer(&scOffset)),
		uintptr(unsafe.Pointer(&size)),
		inheritPerms,
		0,
		pagePerms,
	)
	if err != 0 {
		return 0, fmt.Errorf("%s returned %0x", proc, uint32(err))
	} else if scBase == 0 {
		return 0, fmt.Errorf("%s failed for unknown reason", proc)
	}

	return scBase, nil
}

func NtUnmapViewSection(hndl windows.Handle, base uintptr) error {
	var proc string = "NtUnmapViewOfSection"
	var ntdll *windows.LazyDLL

	ntdll = windows.NewLazySystemDLL("ntdll")
	err, _, _ := ntdll.NewProc(proc).Call(
		uintptr(hndl),
		base,
	)
	if err != 0 {
		return fmt.Errorf("ERROR Unmap")
	}
	return nil
}
