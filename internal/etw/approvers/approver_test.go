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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sys/windows"
)

func makeRecord(providerID windows.GUID, opcode uint8, eventID uint16, buf []byte) *etw.EventRecord {
	b := make([]byte, len(buf))
	copy(b, buf)
	r := &etw.EventRecord{}
	r.Header.ProviderID = providerID
	r.Header.EventDescriptor.Opcode = opcode
	r.Header.EventDescriptor.ID = eventID
	r.BufferLen = uint16(len(b))
	if len(b) > 0 {
		r.Buffer = uintptr(unsafe.Pointer(&b[0]))
	}
	return r
}

func TestApproversNoApprovers(t *testing.T) {
	p := Approvers{approvers: make([]Approver, 0)}
	r := &etw.EventRecord{}
	rec, approved := p.Approve(r)
	assert.True(t, approved)
	assert.Equal(t, r, rec)
}

func TestApproversChainPassesEnrichedRecord(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Paths: map[string][]string{
				"IMATCHES": {`C:\Windows\*`},
			},
		},
	}

	p := New(psnap, rules, nil)

	r := &etw.EventRecord{}
	r.Header.ProviderID = etw.WindowsKernelProcessGUID
	rec, approved := p.Approve(r)
	assert.True(t, approved)
	assert.Equal(t, r, rec)
}

func TestApproversFirstApproverRejectsShortCircuits(t *testing.T) {
	callCount := 0
	first := &mockApprover{fn: func(r *etw.EventRecord) (*etw.EventRecord, bool) {
		callCount++
		return r, false
	}}
	second := &mockApprover{fn: func(r *etw.EventRecord) (*etw.EventRecord, bool) {
		callCount++
		return r, true
	}}

	p := Approvers{approvers: []Approver{first, second}}
	r := &etw.EventRecord{}

	_, approved := p.Approve(r)
	assert.False(t, approved)
	assert.Equal(t, 1, callCount, "second approver should not be called")
}

func TestApproversCleanupDelegatesToFS(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	p := New(psnap, nil, nil)

	// enqueue a CreateFile
	cr := createFileRecord(t, createBuf)
	p.Approve(cr)
	assert.Equal(t, 1, len(p.fs.irps))

	// simulate consumer calling cleanup with the returned CreateFile record
	irp := p.fs.irps[*(*uint64)(unsafe.Pointer(&createBuf[0]))]
	p.Cleanup(irp.rec)
	assert.Equal(t, 0, len(p.fs.irps))
}

func TestApproversFileEventFullFlow(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	p := New(psnap, nil, nil)

	// CreateFile is suppressed and stored
	cr := createFileRecord(t, createBuf)
	_, approved := p.Approve(cr)
	assert.False(t, approved, "CreateFile should be put in queue")
	assert.Equal(t, 1, len(p.fs.irps))

	// FileOpEnd with matching IRP releases stored CreateFile
	foe := buildMatchingFileOpEnd(t, createBuf, uint64(windows.FILE_CREATE))
	rec, approved := p.Approve(foe)
	assert.True(t, approved, "Pending CreateFile should be approved")
	assert.Equal(t, event.CreateFileID, rec.Header.EventDescriptor.Opcode,
		"should return stored CreateFile record")
	assert.NotNil(t, rec.ExtendedData, "extended data should be attached")
}

func TestApproversFileEventWithRulesApproved(t *testing.T) {
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Paths: map[string][]string{
				"ICONTAINS": {`Windows\AppCompat`},
			},
		},
	}

	psnap := &ps.SnapshotterMock{}
	p := New(psnap, rules, nil)

	cr := createFileRecord(t, createBuf)
	p.Approve(cr)
	assert.Equal(t, 1, len(p.fs.irps))

	foe := buildMatchingFileOpEnd(t, createBuf, uint64(windows.FILE_OPEN))
	rec, approved := p.Approve(foe)
	assert.True(t, approved, "Pending CreateFile should be approved")
	assert.Equal(t, event.CreateFileID, rec.Header.EventDescriptor.Opcode,
		"should return stored CreateFile record")
	assert.NotNil(t, rec.ExtendedData, "extended data should be attached")
}

func TestApproversFileEventWithRulesRejected(t *testing.T) {
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Extensions: map[string][]string{
				"IN": {".exe", ".cpl"},
			},
		},
	}

	psnap := &ps.SnapshotterMock{}
	p := New(psnap, rules, nil)

	cr := createFileRecord(t, createBuf)
	p.Approve(cr)
	assert.Equal(t, 1, len(p.fs.irps))

	foe := buildMatchingFileOpEnd(t, createBuf, uint64(windows.FILE_OPEN))
	_, approved := p.Approve(foe)
	assert.False(t, approved, "Pending CreateFile shouldn't be approved")
}

func TestApproversRegistryEventNoRulesApprovesAll(t *testing.T) {
	psnap := &ps.SnapshotterMock{}

	p := New(psnap, nil, nil)
	r := makeRecord(event.RegistryEventGUID, event.RegOpenKeyID, 0, regOpenKeyBuf)

	_, approved := p.Approve(r)
	assert.True(t, approved)
}

func TestApproversRegistryEventWithRulesApproved(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Keys: map[string][]string{
				"IMATCHES": {`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\*`},
			},
		},
	}

	p := New(psnap, rules, nil)

	k := makeRecord(event.RegistryEventGUID, event.RegCreateKCBID, 0, regCreateKCBBuf)
	r := makeRecord(event.RegistryEventGUID, event.RegOpenKeyID, 0, regOpenKeyBuf)

	// first send the RegCreateKCB event to store the KCB mapping
	_, approved := p.Approve(k)
	assert.True(t, approved)

	_, approved = p.Approve(r)
	assert.True(t, approved)
}

func TestApproversRegistryEventWithRulesRejected(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Keys: map[string][]string{
				"IMATCHES": {`HKEY_LOCAL_MACHINE\SYSTEM\*`},
			},
		},
	}

	p := New(psnap, rules, nil)

	k := makeRecord(event.RegistryEventGUID, event.RegCreateKCBID, 0, regCreateKCBBuf)
	r := makeRecord(event.RegistryEventGUID, event.RegOpenKeyID, 0, regOpenKeyBuf)

	p.Approve(k)

	_, approved := p.Approve(r)
	assert.False(t, approved)
}

func TestApproversProcEventNoRulesApprovesAll(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	p := New(psnap, nil, nil)

	buf := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&buf[0])) = uint32(1234)
	r := makeRecord(event.AuditAPIEventGUID, 0, event.OpenProcessID, buf)
	r.Header.ProcessID = 1234

	_, approved := p.Approve(r)
	assert.True(t, approved)
	psnap.AssertNotCalled(t, "Find", mock.Anything)
}

func TestApproversProcEventWithRulesApproved(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Executables: map[string][]string{
				"IMATCHES": {`?:\Windows\System32\*`},
			},
		},
	}

	p := New(psnap, rules, nil)

	const pid = uint32(1234)
	psnap.On("Find", pid).Return(true, &pstypes.PS{
		Exe: `C:\Windows\System32\svchost.exe`,
	})

	buf := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&buf[0])) = pid
	r := makeRecord(event.AuditAPIEventGUID, 0, event.OpenProcessID, buf)
	r.Header.ProcessID = pid

	_, approved := p.Approve(r)
	assert.True(t, approved)
}

func TestApproversProcEventWithRulesRejected(t *testing.T) {
	psnap := &ps.SnapshotterMock{}
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Executables: map[string][]string{
				"IMATCHES": {`C:\Windows\System32\*`},
			},
		},
	}
	p := New(psnap, rules, nil)

	const pid = uint32(5678)
	psnap.On("Find", pid).Return(true, &pstypes.PS{
		Exe: `C:\Users\Administrator\cmd.exe`,
	})

	buf := make([]byte, 4)
	*(*uint32)(unsafe.Pointer(&buf[0])) = pid
	r := makeRecord(event.AuditAPIEventGUID, 0, event.OpenProcessID, buf)
	r.Header.ProcessID = pid

	_, approved := p.Approve(r)
	assert.False(t, approved)
}

func TestApproversMatchPredicate(t *testing.T) {
	a := &approver{}
	tests := []struct {
		name string
		m    map[string][]string
		val  string
		want bool
	}{
		{
			name: "imatches wildcard hit",
			m:    map[string][]string{"IMATCHES": {`C:\Windows\*`}},
			val:  `C:\Windows\System32\ntdll.dll`,
			want: true,
		},
		{
			name: "imatches wildcard miss",
			m:    map[string][]string{"IMATCHES": {`C:\Windows\*`}},
			val:  `C:\Users\Administrator\cmd.exe`,
			want: false,
		},
		{
			name: "imatches case insensitive",
			m:    map[string][]string{"IMATCHES": {`c:\windows\*`}},
			val:  `C:\WINDOWS\System32\ntdll.dll`,
			want: true,
		},
		{
			name: "icontains hit",
			m:    map[string][]string{"ICONTAINS": {"svchost"}},
			val:  `C:\Windows\System32\svchost.exe`,
			want: true,
		},
		{
			name: "icontains case insensitive",
			m:    map[string][]string{"ICONTAINS": {"SVCHOST"}},
			val:  `C:\Windows\System32\svchost.exe`,
			want: true,
		},
		{
			name: "icontains miss",
			m:    map[string][]string{"ICONTAINS": {"evil"}},
			val:  `C:\Windows\System32\svchost.exe`,
			want: false,
		},
		{
			name: "eq hit",
			m:    map[string][]string{"=": {`C:\Windows\System32\svchost.exe`}},
			val:  `C:\Windows\System32\svchost.exe`,
			want: true,
		},
		{
			name: "eq miss",
			m:    map[string][]string{"=": {`C:\Windows\System32\svchost.exe`}},
			val:  `C:\Windows\System32\lsass.exe`,
			want: false,
		},
		{
			name: "ieq hit",
			m:    map[string][]string{"~=": {`C:\Windows\System32\svchost.exe`}},
			val:  `C:\Windows\System32\svchost.exe`,
			want: true,
		},
		{
			name: "multiple patterns first hits",
			m: map[string][]string{
				"IMATCHES": {`C:\Windows\*`, `C:\System32\*`},
			},
			val:  `C:\Windows\notepad.exe`,
			want: true,
		},
		{
			name: "multiple operators one hits",
			m: map[string][]string{
				"IMATCHES":  {`C:\System32\*`},
				"ICONTAINS": {"notepad"},
			},
			val:  `C:\Windows\notepad.exe`,
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := a.matchPredicate(tt.m, tt.val)
			assert.Equal(t, tt.want, got)
		})
	}
}

// mockApprover is a simple test double for the Approver interface
type mockApprover struct {
	fn func(r *etw.EventRecord) (*etw.EventRecord, bool)
}

func (m *mockApprover) Approve(r *etw.EventRecord) (*etw.EventRecord, bool) {
	return m.fn(r)
}
