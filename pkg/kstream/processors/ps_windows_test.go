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
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
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
		e          *kevent.Kevent
		psnap      func() *ps.SnapshotterMock
		assertions func(*kevent.Kevent, *testing.T, *ps.SnapshotterMock)
	}{
		{
			"create exe parameter from cmdline",
			&kevent.Kevent{
				Type: ktypes.CreateProcess,
				Kparams: kevent.Kparams{
					kparams.Cmdline:   {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost.exe -k RPCSS"},
					kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(1023)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Write", mock.Anything).Return(nil)
				return psnap
			},
			func(e *kevent.Kevent, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Kparams.Contains(kparams.Exe))
				require.Equal(t, "C:\\Windows\\system32\\svchost.exe", e.GetParamAsString(kparams.Exe))
				psnap.AssertNumberOfCalls(t, "Write", 1)
			},
		},
		{
			"complete exe for system procs",
			&kevent.Kevent{
				Type: ktypes.CreateProcess,
				Kparams: kevent.Kparams{
					kparams.Cmdline:     {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: "csrss.exe"},
					kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "csrss.exe"},
					kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(676)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Write", mock.Anything).Return(nil)
				return psnap
			},
			func(e *kevent.Kevent, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Kparams.Contains(kparams.Exe))
				require.Equal(t, "csrss.exe", e.GetParamAsString(kparams.Cmdline))
				require.Equal(t, "C:\\Windows\\System32\\csrss.exe", e.GetParamAsString(kparams.Exe))
				psnap.AssertNumberOfCalls(t, "Write", 1)
			},
		},
		{
			"clean quoted executable path",
			&kevent.Kevent{
				Type: ktypes.CreateProcess,
				Kparams: kevent.Kparams{
					kparams.Cmdline:   {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: "\"C:\\Windows\\System32\\smss.exe\""},
					kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(760)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Write", mock.Anything).Return(nil)
				return psnap
			},
			func(e *kevent.Kevent, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Kparams.Contains(kparams.Exe))
				require.Equal(t, "\"C:\\Windows\\System32\\smss.exe\"", e.GetParamAsString(kparams.Cmdline))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(kparams.Exe))
				psnap.AssertNumberOfCalls(t, "Write", 1)
			},
		},
		{
			"expand SystemRoot in executable path",
			&kevent.Kevent{
				Type: ktypes.CreateProcess,
				Kparams: kevent.Kparams{
					kparams.Cmdline:   {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `\SystemRoot\System32\smss.exe`},
					kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(760)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Write", mock.Anything).Return(nil)
				return psnap
			},
			func(e *kevent.Kevent, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Kparams.Contains(kparams.Exe))
				require.Equal(t, `\SystemRoot\System32\smss.exe`, e.GetParamAsString(kparams.Cmdline))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(kparams.Exe))
				psnap.AssertNumberOfCalls(t, "Write", 1)
			},
		},
		{
			"add process start time parameter",
			&kevent.Kevent{
				Type:      ktypes.CreateProcess,
				Timestamp: time.Now(),
				Kparams: kevent.Kparams{
					kparams.Cmdline:   {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `C:\Program Files\Fibratus\fibratus.exe`},
					kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(os.Getpid())},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Write", mock.Anything).Return(nil)
				return psnap
			},
			func(e *kevent.Kevent, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Kparams.Contains(kparams.StartTime))
				require.NotEqual(t, e.Timestamp, e.Kparams.MustGetTime(kparams.StartTime))
			},
		},
		{
			"terminate process",
			&kevent.Kevent{
				Type: ktypes.TerminateProcess,
				Kparams: kevent.Kparams{
					kparams.Cmdline:   {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `\SystemRoot\System32\smss.exe`},
					kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(760)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("Remove", mock.Anything).Return(nil)
				return psnap
			},
			func(e *kevent.Kevent, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Kparams.Contains(kparams.Exe))
				require.Equal(t, `\SystemRoot\System32\smss.exe`, e.GetParamAsString(kparams.Cmdline))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(kparams.Exe))
				psnap.AssertNumberOfCalls(t, "Remove", 1)
				psnap.AssertNotCalled(t, "Write")
			},
		},
		{
			"create thread",
			&kevent.Kevent{
				Type: ktypes.CreateThread,
				Kparams: kevent.Kparams{
					kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(760)},
					kparams.ThreadID:  {Name: kparams.ThreadID, Type: kparams.TID, Value: uint32(10234)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("FindAndPut", uint32(760)).Return(&pstypes.PS{Exe: "C:\\Windows\\System32\\smss.exe"})
				psnap.On("AddThread", mock.Anything).Return(nil)
				return psnap
			},
			func(e *kevent.Kevent, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Kparams.Contains(kparams.Exe))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(kparams.Exe))
				psnap.AssertNumberOfCalls(t, "AddThread", 1)
			},
		},
		{
			"terminate thread",
			&kevent.Kevent{
				Type: ktypes.TerminateThread,
				Kparams: kevent.Kparams{
					kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(760)},
					kparams.ThreadID:  {Name: kparams.ThreadID, Type: kparams.TID, Value: uint32(10234)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("FindAndPut", uint32(760)).Return(&pstypes.PS{Exe: "C:\\Windows\\System32\\smss.exe"})
				psnap.On("RemoveThread", uint32(760), uint32(10234)).Return(nil)
				return psnap
			},
			func(e *kevent.Kevent, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Kparams.Contains(kparams.Exe))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(kparams.Exe))
				psnap.AssertNumberOfCalls(t, "RemoveThread", 1)
				psnap.AssertNotCalled(t, "AddThread")
			},
		},
		{
			"open process",
			&kevent.Kevent{
				Type: ktypes.OpenProcess,
				Kparams: kevent.Kparams{
					kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(760)},
				},
			},
			func() *ps.SnapshotterMock {
				psnap := new(ps.SnapshotterMock)
				psnap.On("FindAndPut", uint32(760)).Return(&pstypes.PS{Name: "smss.exe", Exe: "C:\\Windows\\System32\\smss.exe"})
				return psnap
			},
			func(e *kevent.Kevent, t *testing.T, psnap *ps.SnapshotterMock) {
				require.True(t, e.Kparams.Contains(kparams.Exe))
				require.True(t, e.Kparams.Contains(kparams.ProcessName))
				require.Equal(t, "C:\\Windows\\System32\\smss.exe", e.GetParamAsString(kparams.Exe))
				require.Equal(t, "smss.exe", e.GetParamAsString(kparams.ProcessName))
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
