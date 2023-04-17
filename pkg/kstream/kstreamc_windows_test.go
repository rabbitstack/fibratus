// /*
// * Copyright 2019-2020 by Nedim Sabic Sabic
// * https://www.fibratus.io
// * All Rights Reserved.
// *
// * Licensed under the Apache License, Version 2.0 (the "License");
// * you may not use this file except in compliance with the License.
// * You may obtain a copy of the License at
// *
// *  http://www.apache.org/licenses/LICENSE-2.0
// *
// * Unless required by applicable law or agreed to in writing, software
// * distributed under the License is distributed on an "AS IS" BASIS,
// * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// * See the License for the specific language governing permissions and
// * limitations under the License.
// */
package kstream

import (
	"context"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/handle"
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
						Addr: ":8090",
					}
					mux := http.NewServeMux()
					mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {})
					time.AfterFunc(time.Second*2, func() {
						_, _ = http.Get("http://localhost:8090")
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
	psnap.On("FindAndPut", mock.Anything).Return(&pstypes.PS{})
	psnap.On("Find", mock.Anything).Return(true, &pstypes.PS{})

	hsnap := new(handle.SnapshotterMock)
	kstreamConfig := config.KstreamConfig{
		EnableThreadKevents:   true,
		EnableImageKevents:    true,
		EnableFileIOKevents:   true,
		EnableNetKevents:      true,
		EnableRegistryKevents: true,
	}

	kctrl := NewKtraceController(kstreamConfig)
	require.NoError(t, kctrl.StartKtrace())
	kstreamc := NewConsumer(psnap, hsnap, &config.Config{Kstream: kstreamConfig, Filters: &config.Filters{}})
	require.NoError(t, kstreamc.OpenKstream(kctrl.Traces()))

	time.Sleep(time.Second * 2)

	for _, tt := range tests {
		gen := tt.gen
		if gen != nil {
			require.NoError(t, gen())
		}
	}

	ntests := len(tests)
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
		case <-time.After(time.Duration(ntests) * time.Minute):
			for _, tt := range tests {
				if !tt.completed {
					t.Logf("FAIL: %s", tt.name)
				}
			}
			t.Fatal("FAIL: TestConsumerEvents")
		}
	}
}

//
//import (
//	"encoding/gob"
//	"github.com/rabbitstack/fibratus/pkg/config"
//	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
//	"github.com/rabbitstack/fibratus/pkg/handle"
//	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
//	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
//	"github.com/rabbitstack/fibratus/pkg/ps"
//	"github.com/rabbitstack/fibratus/pkg/ps/types"
//	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
//	"github.com/rabbitstack/fibratus/pkg/syscall/tdh"
//	"github.com/stretchr/testify/assert"
//	"github.com/stretchr/testify/mock"
//	"github.com/stretchr/testify/require"
//	"net"
//	"os"
//	"testing"
//	"time"
//	"unsafe"
//)
//
//func TestOpenKstream(t *testing.T) {
//	psnap := new(ps.SnapshotterMock)
//	hsnap := new(handle.SnapshotterMock)
//	ktraceController := NewKtraceController(config.KstreamConfig{})
//	kstreamc := NewConsumer(ktraceController, psnap, hsnap, &config.Config{Filters: &config.Filters{}})
//	openTrace = func(ktrace etw.EventTraceLogfile) etw.TraceHandle {
//		return etw.TraceHandle(2)
//	}
//	processTrace = func(handle etw.TraceHandle) error {
//		return nil
//	}
//	traces := map[string]TraceSession{
//		etw.KernelLoggerSession: {},
//	}
//	err := kstreamc.OpenKstream(traces)
//	require.NoError(t, err)
//}
//
//func TestOpenKstreamInvalidHandle(t *testing.T) {
//	psnap := new(ps.SnapshotterMock)
//	hsnap := new(handle.SnapshotterMock)
//	ktraceController := NewKtraceController(config.KstreamConfig{})
//	kstreamc := NewConsumer(ktraceController, psnap, hsnap, &config.Config{Filters: &config.Filters{}})
//	openTrace = func(ktrace etw.EventTraceLogfile) etw.TraceHandle {
//		return etw.TraceHandle(0xffffffffffffffff)
//	}
//	traces := map[string]TraceSession{
//		etw.KernelLoggerSession: {Name: etw.KernelLoggerSession, GUID: etw.KernelTraceControlGUID},
//	}
//	err := kstreamc.OpenKstream(traces)
//	require.Error(t, err)
//}
//
//func TestOpenKstreamKsessionNotRunning(t *testing.T) {
//	psnap := new(ps.SnapshotterMock)
//	hsnap := new(handle.SnapshotterMock)
//	ktraceController := NewKtraceController(config.KstreamConfig{})
//	kstreamc := NewConsumer(ktraceController, psnap, hsnap, &config.Config{Filters: &config.Filters{}})
//	openTrace = func(ktrace etw.EventTraceLogfile) etw.TraceHandle {
//		return etw.TraceHandle(2)
//	}
//	processTrace = func(handle etw.TraceHandle) error {
//		return kerrors.ErrKsessionNotRunning
//	}
//	traces := map[string]TraceSession{
//		etw.KernelLoggerSession: {},
//	}
//	err := kstreamc.OpenKstream(traces)
//	require.NoError(t, err)
//	err = <-kstreamc.Errors()
//	assert.EqualError(t, err, "kernel session from which you are trying to consume events in real time is not running")
//}
//
//func TestProcessKevent(t *testing.T) {
//	psnap := new(ps.SnapshotterMock)
//	hsnap := new(handle.SnapshotterMock)
//	ktraceController := NewKtraceController(config.KstreamConfig{})
//	kstreamc := NewConsumer(ktraceController, psnap, hsnap, &config.Config{Filters: &config.Filters{}})
//
//	psnap.On("Find", mock.Anything).Return(&types.PS{Name: "cmd.exe"})
//
//	openTrace = func(ktrace etw.EventTraceLogfile) etw.TraceHandle {
//		return etw.TraceHandle(2)
//	}
//	processTrace = func(handle etw.TraceHandle) error {
//		return nil
//	}
//	getPropertySize = func(evt *etw.EventRecord, descriptor *tdh.PropertyDataDescriptor) (uint32, error) {
//		return uint32(10), nil
//	}
//	getProperty = func(evt *etw.EventRecord, descriptor *tdh.PropertyDataDescriptor, size uint32, buffer []byte) error {
//		return nil
//	}
//
//	psnap.On("Write", mock.Anything).Return(nil)
//
//	f, err := os.Open("./_fixtures/snapshots/create-process.gob")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	dec := gob.NewDecoder(f)
//	var evt etw.EventRecord
//	err = dec.Decode(&evt)
//	if err != nil {
//		t.Fatal(err)
//	}
//	done := make(chan struct{}, 1)
//
//	go func() {
//		defer func() {
//			done <- struct{}{}
//		}()
//		kevt := <-kstreamc.Events()
//
//		assert.Equal(t, ktypes.Process, kevt.Category)
//		assert.Equal(t, uint32(9828), kevt.Tid)
//		assert.Equal(t, uint8(5), kevt.CPU)
//		assert.Equal(t, ktypes.CreateProcess, kevt.Type)
//		assert.Equal(t, "CreateProcess", kevt.Name)
//		assert.Equal(t, "Creates a new process and its primary thread", kevt.Description)
//
//		ts, err := time.Parse("2006-01-02 15:04:05.0000000 -0700 CEST", "2019-04-05 16:10:36.5225778 +0200 CEST")
//		require.NoError(t, err)
//		assert.Equal(t, ts.Year(), kevt.Timestamp.Year())
//		assert.Equal(t, ts.Month(), kevt.Timestamp.Month())
//		assert.Equal(t, ts.Day(), kevt.Timestamp.Day())
//		assert.Equal(t, ts.Minute(), kevt.Timestamp.Minute())
//		assert.Equal(t, ts.Second(), kevt.Timestamp.Second())
//		assert.Equal(t, ts.Nanosecond(), kevt.Timestamp.Nanosecond())
//		assert.Len(t, kevt.Kparams, 9)
//
//		assert.True(t, kevt.Kparams.Contains(kparams.DTB))
//		assert.True(t, kevt.Kparams.Contains(kparams.ProcessName))
//	}()
//
//	err = kstreamc.(*kstreamConsumer).processKevent(&evt)
//	require.NoError(t, err)
//
//	<-done
//}
//
