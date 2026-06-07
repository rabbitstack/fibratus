/*
 * Copyright 2020-present by Nedim Sabic Sabic
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

package approvers

import (
	"testing"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sys/windows"
)

func procRecord(opcode uint8, eventID uint16, pid uint32, providerID windows.GUID) *etw.EventRecord {
	buf := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&buf[0])) = pid
	r := &etw.EventRecord{}
	r.Header.ProviderID = providerID
	r.Header.EventDescriptor.Opcode = opcode
	r.Header.EventDescriptor.ID = eventID
	r.Header.ProcessID = pid
	r.BufferLen = uint16(len(buf))
	r.Buffer = uintptr(unsafe.Pointer(&buf[0]))
	return r
}

func openProcRecord(pid uint32) *etw.EventRecord {
	r := procRecord(0, event.OpenProcessID, pid, event.AuditAPIEventGUID)
	return r
}

func openThreadRecord(callerPID, targetPID uint32) *etw.EventRecord {
	buf := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&buf[0])) = targetPID
	r := &etw.EventRecord{}
	r.Header.ProviderID = event.AuditAPIEventGUID
	r.Header.EventDescriptor.ID = event.OpenThreadID
	r.Header.ProcessID = callerPID
	r.BufferLen = uint16(len(buf))
	r.Buffer = uintptr(unsafe.Pointer(&buf[0]))
	return r
}

func newTestProcApprover(psnap *ps.SnapshotterMock, r *config.RulesCompileResult) *proc {
	return newProcApprover(psnap, r).(*proc)
}

func TestProcApproverNonAuditAPIEvent(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	a := newTestProcApprover(psnap, nil)

	r := &etw.EventRecord{}
	r.Header.ProviderID = event.FileEventGUID
	rec, approved := a.Approve(r)
	if !approved {
		t.Error("non-AuditAPI event should be approved")
	}
	if rec != r {
		t.Error("should return original record")
	}
	psnap.AssertNotCalled(t, "Find", mock.Anything)
}

func TestProcApproverNonOpenProcessOrThreadID(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	a := newTestProcApprover(psnap, nil)

	r := &etw.EventRecord{}
	r.Header.ProviderID = event.AuditAPIEventGUID
	r.Header.EventDescriptor.ID = 9999 // some other event ID
	rec, approved := a.Approve(r)
	if !approved {
		t.Error("non-OpenProcess/Thread event should be approved")
	}
	if rec != r {
		t.Error("should return original record")
	}
	psnap.AssertNotCalled(t, "Find", mock.Anything)
}

func TestProcApproverOpenRemoteThreadAlwaysApproved(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	a := newTestProcApprover(psnap, nil)

	// caller PID != target PID = remote thread open, always allow
	r := openThreadRecord(1234, 5678)
	_, approved := a.Approve(r)
	if !approved {
		t.Error("remote thread open should always be approved")
	}
	psnap.AssertNotCalled(t, "Find", mock.Anything)
}

func TestProcApproverOpenProcessProcessNotInSnapshot(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	a := newTestProcApprover(psnap, nil)

	const pid = uint32(1234)
	psnap.On("Find", pid).Return(false, (*pstypes.PS)(nil))

	r := openProcRecord(pid)
	_, approved := a.Approve(r)
	if !approved {
		t.Error("process not in snapshot should be approved")
	}
	psnap.AssertCalled(t, "Find", pid)
}

func TestProcApproverOpenProcessNilPS(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	a := newTestProcApprover(psnap, nil)

	const pid = uint32(1234)
	psnap.On("Find", pid).Return(true, (*pstypes.PS)(nil))

	r := openProcRecord(pid)
	_, approved := a.Approve(r)
	if !approved {
		t.Error("nil PS entry should be approved")
	}
}

func TestProcApproverOpenProcessExeApproved(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Executables: map[string][]string{
				"IMATCHES": {`C:\Windows\System32\*`},
			},
		},
	}
	a := newTestProcApprover(psnap, rules)

	const pid = uint32(1234)
	psnap.On("Find", pid).Return(true, &pstypes.PS{Exe: `C:\Windows\System32\svchost.exe`})

	r := openProcRecord(pid)
	_, approved := a.Approve(r)
	if !approved {
		t.Error("matching executable should be approved")
	}
}

func TestProcApproverOpenProcessExeRejected(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Executables: map[string][]string{
				"IMATCHES": {`C:\Windows\System32\*`},
			},
		},
	}
	a := newTestProcApprover(psnap, rules)

	const pid = uint32(5678)
	psnap.On("Find", pid).Return(true, &pstypes.PS{Exe: `C:\Users\Administrator\cmd.exe`})

	r := openProcRecord(pid)
	_, approved := a.Approve(r)
	if approved {
		t.Error("non-matching executable should be rejected")
	}
}

func TestProcApproverOpenProcessEmptyExeApproved(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Executables: map[string][]string{
				"IMATCHES": {`C:\Windows\*`},
			},
		},
	}
	a := newTestProcApprover(psnap, rules)

	const pid = uint32(9999)
	psnap.On("Find", pid).Return(true, &pstypes.PS{Exe: ""})

	r := openProcRecord(pid)
	_, approved := a.Approve(r)
	if !approved {
		t.Error("empty exe should be automatically approved")
	}
}

func TestProcApproverOpenThreadSameProcessExeApproved(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Executables: map[string][]string{
				"IMATCHES": {`C:\Windows\*`},
			},
		},
	}

	const pid = uint32(888)
	a := newTestProcApprover(psnap, rules)
	r := openThreadRecord(pid, pid)

	psnap.On("Find", pid).Return(true, &pstypes.PS{Exe: `C:\Windows\System32\lsass.exe`})

	_, approved := a.Approve(r)
	if !approved {
		t.Error("self thread open with matching exe should be approved")
	}
}

func TestProcApproverOpenThreadSameProcessExeRejected(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Executables: map[string][]string{
				"IMATCHES": {`C:\Windows\*`},
			},
		},
	}
	const pid = uint32(777)

	a := newTestProcApprover(psnap, rules)
	r := openThreadRecord(pid, pid)

	psnap.On("Find", pid).Return(true, &pstypes.PS{Exe: `C:\suspicious\inject.exe`})

	_, approved := a.Approve(r)
	if approved {
		t.Error("self thread open with non-matching exe should be rejected")
	}
}
