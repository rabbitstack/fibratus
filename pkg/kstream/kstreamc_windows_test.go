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
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

	kctrl := NewKtraceController(kstreamConfig)
	require.NoError(t, kctrl.StartKtrace())
	defer kctrl.CloseKtrace()
	kstreamc := NewConsumer(psnap, hsnap, &config.Config{
		Kstream:  kstreamConfig,
		KcapFile: "fake.kcap", // simulate capture to receive state/rundown events
		Filters:  &config.Filters{},
	})
	require.NoError(t, kstreamc.OpenKstream(kctrl.Traces()))
	defer kstreamc.CloseKstream()

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
		case _ = <-kstreamc.Errors():
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
				return e.IsLoadImage() && strings.EqualFold(img, e.GetParamAsString(kparams.ImageFilename))
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
					e.GetParamAsString(kparams.FileOperation) == "CREATE"
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
						_, _ = http.Get("http://localhost:18090")
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

	kstreamConfig := config.KstreamConfig{
		EnableThreadKevents:   true,
		EnableImageKevents:    true,
		EnableFileIOKevents:   true,
		EnableNetKevents:      true,
		EnableRegistryKevents: true,
	}

	kctrl := NewKtraceController(kstreamConfig)
	require.NoError(t, kctrl.StartKtrace())
	defer kctrl.CloseKtrace()
	kstreamc := NewConsumer(psnap, hsnap, &config.Config{Kstream: kstreamConfig, Filters: &config.Filters{}})
	require.NoError(t, kstreamc.OpenKstream(kctrl.Traces()))
	defer kstreamc.CloseKstream()

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
