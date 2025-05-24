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

package processors

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func TestPsProcessor(t *testing.T) {
	require.NoError(t, os.Setenv("SystemRoot", "C:\\Windows"))

	var tests = []struct {
		name       string
		e          *event.Event
		psnap      func() *ps.SnapshotterMock
		assertions func(*event.Event, *testing.T, *ps.SnapshotterMock)
	}{
		{
			"create exe parameter from cmdline",
			&event.Event{
				Type: event.CreateProcess,
				Params: event.Params{
					params.Cmdline:   {Name: params.Cmdline, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k RPCSS"},
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(1023)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Write", mock.Anything).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Params.Contains(params.Exe))
				require.Equal(t, "C:\\Windows\\system32\\svchost.exe", e.GetParamAsString(params.Exe))
				psnap.AssertNumberOfCalls(t, "Write", 1)
			},
		},
		{
			"complete exe for system procs",
			&event.Event{
				Type: event.CreateProcess,
				Params: event.Params{
					params.Cmdline:     {Name: params.Cmdline, Type: params.UnicodeString, Value: "csrss.exe"},
					params.ProcessName: {Name: params.ProcessName, Type: params.AnsiString, Value: "csrss.exe"},
					params.ProcessID:   {Name: params.ProcessID, Type: params.PID, Value: uint32(676)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Write", mock.Anything).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Params.Contains(params.Exe))
				require.Equal(t, "csrss.exe", e.GetParamAsString(params.Cmdline))
				require.Equal(t, "C:\\Windows\\System32\\csrss.exe", e.GetParamAsString(params.Exe))
				psnap.AssertNumberOfCalls(t, "Write", 1)
			},
		},
		{
			"clean quoted executable path",
			&event.Event{
				Type: event.CreateProcess,
				Params: event.Params{
					params.Cmdline:   {Name: params.Cmdline, Type: params.UnicodeString, Value: "\"C:\\Windows\\System32\\smss.exe\""},
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(760)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Write", mock.Anything).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Params.Contains(params.Exe))
				require.Equal(t, "\"C:\\Windows\\System32\\smss.exe\"", e.GetParamAsString(params.Cmdline))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(params.Exe))
				psnap.AssertNumberOfCalls(t, "Write", 1)
			},
		},
		{
			"expand SystemRoot in executable path",
			&event.Event{
				Type: event.CreateProcess,
				Params: event.Params{
					params.Cmdline:   {Name: params.Cmdline, Type: params.UnicodeString, Value: `\SystemRoot\System32\smss.exe`},
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(760)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Write", mock.Anything).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Params.Contains(params.Exe))
				require.Equal(t, `\SystemRoot\System32\smss.exe`, e.GetParamAsString(params.Cmdline))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(params.Exe))
				psnap.AssertNumberOfCalls(t, "Write", 1)
			},
		},
		{
			"add process start time parameter",
			&event.Event{
				Type:      event.CreateProcess,
				Timestamp: time.Now(),
				Params: event.Params{
					params.Cmdline:   {Name: params.Cmdline, Type: params.UnicodeString, Value: `C:\Program Files\Fibratus\fibratus.exe`},
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Write", mock.Anything).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Params.Contains(params.StartTime))
				require.NotEqual(t, e.Timestamp, e.Params.MustGetTime(params.StartTime))
			},
		},
		{
			"terminate process",
			&event.Event{
				Type: event.TerminateProcess,
				Params: event.Params{
					params.Cmdline:   {Name: params.Cmdline, Type: params.UnicodeString, Value: `\SystemRoot\System32\smss.exe`},
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(760)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Remove", mock.Anything).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Params.Contains(params.Exe))
				require.Equal(t, `\SystemRoot\System32\smss.exe`, e.GetParamAsString(params.Cmdline))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(params.Exe))
				psnap.AssertNumberOfCalls(t, "Remove", 1)
				psnap.AssertNotCalled(t, "Write")
			},
		},
		{
			"create thread",
			&event.Event{
				Type: event.CreateThread,
				Params: event.Params{
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(760)},
					params.ThreadID:  {Name: params.ThreadID, Type: params.TID, Value: uint32(10234)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("FindAndPut", uint32(760)).Return(&pstypes.PS{Exe: "C:\\Windows\\System32\\smss.exe"})
				psnap.On("AddThread", mock.Anything).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Params.Contains(params.Exe))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(params.Exe))
				psnap.AssertNumberOfCalls(t, "AddThread", 1)
			},
		},
		{
			"terminate thread",
			&event.Event{
				Type: event.TerminateThread,
				Params: event.Params{
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(760)},
					params.ThreadID:  {Name: params.ThreadID, Type: params.TID, Value: uint32(10234)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("FindAndPut", uint32(760)).Return(&pstypes.PS{Exe: "C:\\Windows\\System32\\smss.exe"})
				psnap.On("RemoveThread", uint32(760), uint32(10234)).Return(nil)
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Params.Contains(params.Exe))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(params.Exe))
				psnap.AssertNumberOfCalls(t, "RemoveThread", 1)
				psnap.AssertNotCalled(t, "AddThread")
			},
		},
		{
			"open process",
			&event.Event{
				Type: event.OpenProcess,
				Params: event.Params{
					params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint32(760)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("FindAndPut", uint32(760)).Return(&pstypes.PS{Name: "smss.exe", Exe: "C:\\Windows\\System32\\smss.exe"})
				return psnap
			},
			func(e *event.Event, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Params.Contains(params.Exe))
				require.True(t, e.Params.Contains(params.ProcessName))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(params.Exe))
				require.Equal(t, "smss.exe", e.GetParamAsString(params.ProcessName))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			psnap := tt.psnap()
			p := newPsProcessor(psnap, va.NewRegionProber())
			var err error
			tt.e, _, err = p.ProcessEvent(tt.e)
			require.NoError(t, err)
			tt.assertions(tt.e, t, psnap)
		})
	}
}
