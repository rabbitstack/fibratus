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
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"golang.org/x/sys/windows"
)

// createFileRecord builds an EventRecord for a CreateFile event
// using the provided raw buffer.
func createFileRecord(t *testing.T, buf []byte) *etw.EventRecord {
	t.Helper()
	b := make([]byte, len(buf))
	copy(b, buf)
	r := &etw.EventRecord{}
	r.Header.Timestamp = 250273540393 // matches StackWalk timestamp parameter
	r.Header.ProviderID = event.FileEventGUID
	r.Header.EventDescriptor.Opcode = event.CreateFileID
	r.BufferLen = uint16(len(b))
	r.Buffer = uintptr(unsafe.Pointer(&b[0]))
	// store b to prevent GC
	t.Cleanup(func() { _ = b })
	return r
}

// fileOpEndRecord builds an EventRecord for a FileOpEnd event.
func fileOpEndRecord(t *testing.T, buf []byte) *etw.EventRecord {
	t.Helper()
	b := make([]byte, len(buf))
	copy(b, buf)
	r := &etw.EventRecord{}
	r.Header.ProviderID = event.FileEventGUID
	r.Header.EventDescriptor.Opcode = event.FileOpEndID
	r.BufferLen = uint16(len(b))
	r.Buffer = uintptr(unsafe.Pointer(&b[0]))
	t.Cleanup(func() { _ = b })
	return r
}

func stackwalkRecord(t *testing.T, buf []byte) *etw.EventRecord {
	t.Helper()
	b := make([]byte, len(buf))
	copy(b, buf)
	r := &etw.EventRecord{}
	r.Header.ProviderID = event.StackWalkEventGUID
	r.Header.EventDescriptor.Opcode = event.StackWalkID
	r.BufferLen = uint16(len(b))
	r.Buffer = uintptr(unsafe.Pointer(&b[0]))
	t.Cleanup(func() { _ = b })
	return r
}

var (
	createBuf = []byte{
		200, 7, 94, 150, 141, 215, 255, 255, // Irp
		80, 102, 11, 146, 141, 215, 255, 255, // FileObject
		136, 25, 0, 0, // ThreadId
		36, 128, 0, 3, // Options
		128, 0, 0, 0, // Attributes
		0, 0, 0, 0, // ShareAccess
		// \Device\HarddiskVolume3\WINDOWS\AppCompat\Programs\Amcache.hve
		92, 0,
		68, 0, 101, 0, 118, 0, 105, 0, 99, 0, 101, 0,
		92, 0,
		72, 0, 97, 0, 114, 0, 100, 0, 100, 0, 105, 0,
		115, 0, 107, 0,
		86, 0, 111, 0, 108, 0, 117, 0, 109, 0, 101, 0,
		51, 0,
		92, 0,
		87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0,
		83, 0,
		92, 0,
		65, 0, 112, 0, 112, 0,
		67, 0, 111, 0, 109, 0, 112, 0, 97, 0, 116, 0,
		92, 0,
		80, 0, 114, 0, 111, 0, 103, 0, 114, 0, 97, 0,
		109, 0, 115, 0,
		92, 0,
		65, 0, 109, 0, 99, 0, 97, 0, 99, 0, 104, 0,
		101, 0, 46, 0, 104, 0, 118, 0, 101, 0,
		0, 0,
	}
	opendBuf = []byte{
		248, 240, 61, 151, 141, 215, 255, 255, // Irp
		0, 0, 0, 0, 40, 0, 0, 0, // ExtraInformation
		0, 0, 0, 0, // Status
	}

	stackwalkBuf = []byte{
		41, 41, 119, 69, 58, 0, 0, 0,
		12, 15, 0, 0,
		160, 29, 0, 0,

		148, 12, 254, 189, 5, 248, 255, 255,
		175, 137, 229, 189, 5, 248, 255, 255,
		134, 47, 242, 189, 5, 248, 255, 255,
		36, 109, 255, 80, 5, 248, 255, 255,
		175, 186, 130, 79, 5, 248, 255, 255,
		160, 177, 130, 79, 5, 248, 255, 255,
		224, 104, 137, 79, 5, 248, 255, 255,
		59, 149, 250, 189, 5, 248, 255, 255,
		179, 148, 250, 189, 5, 248, 255, 255,
		59, 168, 73, 190, 5, 248, 255, 255,
		218, 136, 73, 190, 5, 248, 255, 255,
		227, 101, 73, 190, 5, 248, 255, 255,
		196, 202, 73, 190, 5, 248, 255, 255,
		85, 217, 43, 190, 5, 248, 255, 255,

		20, 69, 114, 9, 253, 127, 0, 0,
		31, 51, 25, 6, 253, 127, 0, 0,
		105, 96, 138, 36, 246, 127, 0, 0,
		109, 37, 146, 36, 246, 127, 0, 0,
		227, 37, 146, 36, 246, 127, 0, 0,
	}
)

// buildMatchingFileOpEnd builds a FileOpEnd whose IRP matches the given CreateFile buffer.
func buildMatchingFileOpEnd(t *testing.T, createBuf []byte, disposition uint64) *etw.EventRecord {
	t.Helper()
	// read IRP from createFile buffer (first 8 bytes)
	irp := *(*uint64)(unsafe.Pointer(&createBuf[0]))

	buf := make([]byte, 20)
	*(*uint64)(unsafe.Pointer(&buf[0])) = irp
	*(*uint64)(unsafe.Pointer(&buf[8])) = disposition
	*(*uint32)(unsafe.Pointer(&buf[16])) = 0

	r := &etw.EventRecord{}
	r.Header.ProviderID = event.FileEventGUID
	r.Header.EventDescriptor.Opcode = event.FileOpEndID
	r.BufferLen = uint16(len(buf))
	r.Buffer = uintptr(unsafe.Pointer(&buf[0]))
	t.Cleanup(func() { _ = buf })
	return r
}

func newTestFSApprover(r *config.RulesCompileResult) *fs {
	return newFSApprover(r).(*fs)
}

func TestFSApproverNonFileEvent(t *testing.T) {
	f := newTestFSApprover(nil)
	r := &etw.EventRecord{}
	r.Header.ProviderID = event.ProcessEventGUID
	rec, approved := f.Approve(r)
	if !approved {
		t.Error("non-file event should be approved")
	}
	if rec != r {
		t.Error("non-file event should return original record")
	}
}

func TestFSApproverCreateFileIsEnqueuedAndSuppressed(t *testing.T) {
	f := newTestFSApprover(nil)
	r := createFileRecord(t, createBuf)

	rec, approved := f.Approve(r)
	if approved {
		t.Error("CreateFile should be suppressed")
	}
	if rec != r {
		t.Error("CreateFile should return original record unchanged")
	}
	if len(f.irps) != 1 {
		t.Errorf("expected 1 IRP in map, got %d", len(f.irps))
	}
}

func TestFSApproverFileOpEndNoMatchingIRP(t *testing.T) {
	f := newTestFSApprover(nil)
	// FileOpEnd arrives with no prior CreateFile
	r := fileOpEndRecord(t, opendBuf)
	rec, approved := f.Approve(r)
	if approved {
		t.Error("FileOpEnd with no matching IRP should be suppressed")
	}
	if rec != r {
		t.Error("should return original FileOpEnd record")
	}
}

func TestFSApproverFileOpEndDispositionOutOfRange(t *testing.T) {
	f := newTestFSApprover(nil)
	// first enqueue CreateFile
	f.Approve(createFileRecord(t, createBuf))

	// FileOpEnd with disposition > FILE_MAXIMUM_DISPOSITION
	r := buildMatchingFileOpEnd(t, createBuf, windows.FILE_MAXIMUM_DISPOSITION+1)
	_, approved := f.Approve(r)
	if approved {
		t.Error("FileOpEnd with out-of-range disposition should be suppressed")
	}
}

func TestFSApproverFileOpEndNoRules(t *testing.T) {
	// r == nil means no rules compiled, all events flow through
	f := newTestFSApprover(nil)
	f.Approve(createFileRecord(t, createBuf))

	r := buildMatchingFileOpEnd(t, createBuf, windows.FILE_OPEN)
	rec, approved := f.Approve(r)
	if !approved {
		t.Error("with no rules, all file events should be approved")
	}
	if rec.Header.EventDescriptor.Opcode != event.CreateFileID {
		t.Error("should return stored CreateFile record, not FileOpEnd")
	}
	if rec.ExtendedData == nil {
		t.Error("extended data should be attached to the returned record")
	}
}

func TestFSApproverFileOpEndNonOpenDispositionApprovesWithoutPathCheck(t *testing.T) {
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Paths: map[string][]string{
				"IMATCHES": {`C:\Windows\*`},
			},
		},
	}
	f := newTestFSApprover(rules)
	f.Approve(createFileRecord(t, createBuf))

	// FILE_CREATE disposition should bypass path approvers
	r := buildMatchingFileOpEnd(t, createBuf, windows.FILE_CREATE)
	rec, approved := f.Approve(r)
	if !approved {
		t.Error("non-OPEN disposition should be approved without path check")
	}
	if rec.ExtendedData == nil {
		t.Error("extended data should be attached")
	}
}

func TestFSApproverFileOpEndPathApproverApproved(t *testing.T) {
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Paths: map[string][]string{
				"ICONTAINS": {`windows\appcompat`},
			},
		},
	}
	f := newTestFSApprover(rules)
	f.Approve(createFileRecord(t, createBuf))

	r := buildMatchingFileOpEnd(t, createBuf, windows.FILE_OPEN)
	rec, approved := f.Approve(r)
	if !approved {
		t.Error("path matching approver should approve the event")
	}
	if rec.ExtendedData == nil {
		t.Error("extended data should be attached")
	}
	if len(f.irps) != 1 {
		t.Error("IRP should still be in map until cleanup is called")
	}
}

func TestFSApproverFileOpEndPathApproverRejected(t *testing.T) {
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Paths: map[string][]string{
				"ICONTAINS": {`Windows\System32`},
			},
		},
	}
	f := newTestFSApprover(rules)

	f.Approve(createFileRecord(t, createBuf))

	r := buildMatchingFileOpEnd(t, createBuf, windows.FILE_OPEN)
	_, approved := f.Approve(r)
	if approved {
		t.Error("non-matching path should reject the event")
	}
	if len(f.irps) != 0 {
		t.Error("rejected IRP should be deleted from map immediately")
	}
}

func TestFSApproverCleanup(t *testing.T) {
	f := newTestFSApprover(nil)
	cr := createFileRecord(t, createBuf)
	f.Approve(cr)

	if len(f.irps) != 1 {
		t.Fatalf("expected 1 IRP before cleanup")
	}

	// simulate what consumer does: cleanup with the stored CreateFile record
	irp := f.irps[*(*uint64)(unsafe.Pointer(&createBuf[0]))]
	f.cleanup(irp.rec)

	if len(f.irps) != 0 {
		t.Error("IRP should be removed after cleanup")
	}
}

func TestFSApproverCleanupNonFileEventIsNoop(t *testing.T) {
	f := newTestFSApprover(nil)
	f.Approve(createFileRecord(t, createBuf))

	r := &etw.EventRecord{}
	r.Header.ProviderID = event.ProcessEventGUID
	f.cleanup(r) // should not panic or delete anything

	if len(f.irps) != 1 {
		t.Error("cleanup of non-file event should be a no-op")
	}
}

func TestFSApproverMultipleIRPs(t *testing.T) {
	f := newTestFSApprover(nil)

	// build two different CreateFile buffers with different IRPs
	buf1 := make([]byte, len(createBuf))
	copy(buf1, createBuf)
	buf2 := make([]byte, len(createBuf))
	copy(buf2, createBuf)
	// modify IRP in buf2
	*(*uint64)(unsafe.Pointer(&buf2[0])) = 0xDEADBEEF

	f.Approve(createFileRecord(t, buf1))
	f.Approve(createFileRecord(t, buf2))

	if len(f.irps) != 2 {
		t.Fatalf("expected 2 IRPs in map, got %d", len(f.irps))
	}

	// complete first IRP
	r1 := buildMatchingFileOpEnd(t, buf1, windows.FILE_OPEN)
	_, approved := f.Approve(r1)
	if !approved {
		t.Error("first FileOpEnd should be approved")
	}
	if len(f.irps) != 2 {
		t.Error("second IRP should still be in map")
	}

	// complete second IRP
	r2 := buildMatchingFileOpEnd(t, buf2, windows.FILE_OPEN)
	_, approved = f.Approve(r2)
	if !approved {
		t.Error("second FileOpEnd should be approved")
	}
}
