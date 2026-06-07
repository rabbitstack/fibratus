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
)

var (
	regOpenKeyBuf = []byte{
		248, 104, 16, 11, 5, 0, 0, 0, // Status
		0, 0, 0, 0, 0, 0, 0, 0, // Index
		144, 249, 47, 116, 139, 181, 255, 255, // KCB (offset 16)
		83, 0, 111, 0, 102, 0, 116, 0, // S o f t
		119, 0, 97, 0, 114, 0, 101, 0, // w a r e
		92, 0,
		77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0,
		111, 0, 102, 0, 116, 0,
		92, 0,
		87, 0, 105, 0, 110, 0, 100, 0, 111, 0, 119, 0,
		115, 0,
		92, 0,
		67, 0, 117, 0, 114, 0, 114, 0, 101, 0, 110, 0,
		116, 0, 86, 0, 101, 0, 114, 0, 115, 0, 105, 0,
		111, 0, 110, 0,
		92, 0,
		67, 0, 97, 0, 112, 0, 97, 0, 98, 0, 105, 0,
		108, 0, 105, 0, 116, 0, 121, 0,
		65, 0, 99, 0, 99, 0, 101, 0, 115, 0, 115, 0,
		77, 0, 97, 0, 110, 0, 97, 0, 103, 0, 101, 0,
		114, 0,
		92, 0,
		67, 0, 97, 0, 112, 0, 97, 0, 98, 0, 105, 0,
		108, 0, 105, 0, 116, 0, 105, 0, 101, 0, 115, 0,
		0, 0,
	}
	regCreateKCBBuf = []byte{
		248, 104, 16, 11, 5, 0, 0, 0, // Status
		0, 0, 0, 0, 0, 0, 0, 0, // Index
		144, 249, 47, 116, 139, 181, 255, 255, // KCB (offset 16)
		// \REGISTRY\MACHINE (UTF-16LE)
		92, 0, // '\'
		82, 0, 69, 0, 71, 0, 73, 0, // R E G I
		83, 0, 84, 0, 82, 0, 89, 0, // S T R Y
		92, 0, // '\'
		77, 0, 65, 0, 67, 0, 72, 0, // M A C H
		73, 0, 78, 0, 69, 0, // I N E
		0, 0, // null terminator
	}
)

func registryRecord(t *testing.T, opcode uint8, buf []byte) *etw.EventRecord {
	t.Helper()
	b := make([]byte, len(buf))
	copy(b, buf)
	r := &etw.EventRecord{}
	r.Header.ProviderID = event.RegistryEventGUID
	r.Header.EventDescriptor.Opcode = opcode
	r.BufferLen = uint16(len(b))
	r.Buffer = uintptr(unsafe.Pointer(&b[0]))
	t.Cleanup(func() { _ = b })
	return r
}

// buildKCBRecord builds a RegCreateKCB/RegKCBRundown record with the given KCB key and path.
func buildKCBRecord(t *testing.T, opcode uint8, kcb uint64, path string) *etw.EventRecord {
	t.Helper()
	// layout: 8 bytes status + 8 bytes index + 8 bytes KCB + UTF-16 path
	utf16Path := utf16Encode(path)
	bufLen := 24 + len(utf16Path)
	buf := make([]byte, bufLen)
	*(*uint64)(unsafe.Pointer(&buf[16])) = kcb
	copy(buf[24:], utf16Path)
	r := &etw.EventRecord{}
	r.Header.ProviderID = event.RegistryEventGUID
	r.Header.EventDescriptor.Opcode = opcode
	r.BufferLen = uint16(bufLen)
	r.Buffer = uintptr(unsafe.Pointer(&buf[0]))
	t.Cleanup(func() { _ = buf })
	return r
}

// buildRegOpenKeyRecord builds a RegOpenKey record with given KCB and path.
func buildRegOpenKeyRecord(t *testing.T, kcb uint64, path string) *etw.EventRecord {
	t.Helper()
	utf16Path := utf16Encode(path)
	bufLen := 24 + len(utf16Path)
	buf := make([]byte, bufLen)
	*(*uint64)(unsafe.Pointer(&buf[16])) = kcb
	copy(buf[24:], utf16Path)
	r := &etw.EventRecord{}
	r.Header.ProviderID = event.RegistryEventGUID
	r.Header.EventDescriptor.Opcode = event.RegOpenKeyID
	r.BufferLen = uint16(bufLen)
	r.Buffer = uintptr(unsafe.Pointer(&buf[0]))
	t.Cleanup(func() { _ = buf })
	return r
}

// utf16Encode encodes a string as UTF-16LE with null terminator
func utf16Encode(s string) []byte {
	buf := make([]byte, (len(s)+1)*2)
	for i, c := range s {
		buf[i*2] = byte(c)
		buf[i*2+1] = byte(c >> 8)
	}
	return buf
}

func newTestRegistryApprover(r *config.RulesCompileResult) *registry {
	return newRegistryApprover(r).(*registry)
}

func TestRegistryApproverNonRegistryEvent(t *testing.T) {
	a := newTestRegistryApprover(nil)
	r := &etw.EventRecord{}
	r.Header.ProviderID = event.FileEventGUID
	rec, approved := a.Approve(r)
	if !approved {
		t.Error("non-registry event should be approved")
	}
	if rec != r {
		t.Error("non-registry event should return original record")
	}
}

func TestRegistryApproverRegCreateKCBStoresPath(t *testing.T) {
	a := newTestRegistryApprover(nil)
	const kcb = uint64(0xffb58174f990)
	r := buildKCBRecord(t, event.RegCreateKCBID, kcb, `HKEY_LOCAL_MACHINE\SYSTEM`)
	rec, approved := a.Approve(r)
	if !approved {
		t.Error("RegCreateKCB should be approved")
	}
	if rec != r {
		t.Error("should return original record")
	}
	if got := a.kcbs[kcb]; got != `HKEY_LOCAL_MACHINE\SYSTEM` {
		t.Errorf("KCB path not stored correctly, got %q", got)
	}
}

func TestRegistryApproverRegKCBRundownStoresPath(t *testing.T) {
	a := newTestRegistryApprover(nil)
	const kcb = uint64(0xffb58174f990)
	r := buildKCBRecord(t, event.RegKCBRundownID, kcb, `HKEY_CURRENT_USER\Software`)
	rec, approved := a.Approve(r)
	if !approved {
		t.Error("RegKCBRundown should be approved")
	}
	if rec != r {
		t.Error("should return original record")
	}
	if got := a.kcbs[kcb]; got != `HKEY_CURRENT_USER\Software` {
		t.Errorf("KCB path not stored correctly, got %q", got)
	}
}

func TestRegistryApproverRegDeleteKCBRemovesEntry(t *testing.T) {
	a := newTestRegistryApprover(nil)
	const kcb = uint64(0xffb58174f990)
	// first store it
	a.kcbs[kcb] = `HKEY_LOCAL_MACHINE\SYSTEM`
	r := buildKCBRecord(t, event.RegDeleteKCBID, kcb, "")
	rec, approved := a.Approve(r)
	if !approved {
		t.Error("RegDeleteKCB should be approved")
	}
	if rec != r {
		t.Error("should return original record")
	}
	if _, ok := a.kcbs[kcb]; ok {
		t.Error("KCB entry should be removed after RegDeleteKCB")
	}
}

func TestRegistryApproverNonOpenKeyOpcodeApproved(t *testing.T) {
	a := newTestRegistryApprover(nil)
	r := registryRecord(t, event.RegSetValueID, regOpenKeyBuf)
	_, approved := a.Approve(r)
	if !approved {
		t.Error("non-RegOpenKey registry event should be approved unconditionally")
	}
}

func TestRegistryApproverRegOpenKeyApproved(t *testing.T) {
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Keys: map[string][]string{
				"IMATCHES": {`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\*`},
			},
		},
	}

	a := newTestRegistryApprover(rules)
	r := registryRecord(t, event.RegOpenKeyID, regOpenKeyBuf)

	const kcb = uint64(18446662209287223696)
	a.kcbs[kcb] = `HKEY_LOCAL_MACHINE`

	_, approved := a.Approve(r)
	if !approved {
		t.Error("key matching approver should approve the event")
	}
}

func TestRegistryApproverRegOpenKeyRejected(t *testing.T) {
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Keys: map[string][]string{
				"IMATCHES": {`HKEY_LOCAL_MACHINE\SYSTEM\*`},
			},
		},
	}

	a := newTestRegistryApprover(rules)
	r := registryRecord(t, event.RegOpenKeyID, regOpenKeyBuf)

	const kcb = uint64(18446662209287223696)
	a.kcbs[kcb] = `HKEY_LOCAL_MACHINE`

	_, approved := a.Approve(r)
	if approved {
		t.Error("non-matching key should reject the event")
	}
}

func TestRegistryApproverRegOpenKeyKCBPathPrepended(t *testing.T) {
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Keys: map[string][]string{
				"IMATCHES": {`HKEY_LOCAL_MACHINE\SYSTEM\*`},
			},
		},
	}

	a := newTestRegistryApprover(rules)
	const kcb = uint64(0xffb58174f990)
	// store KCB with a root path
	a.kcbs[kcb] = `\REGISTRY\MACHINE`

	// build RegOpenKey with the same KCB and a relative subkey
	r := buildRegOpenKeyRecord(t, kcb, `SYSTEM\CurrentControlSet`)

	_, approved := a.Approve(r)
	if !approved {
		t.Error("prepended KCB path should be approved")
	}
}

func TestRegistryApproverRegOpenKeyZeroKCBUsesPathDirectly(t *testing.T) {
	rules := &config.RulesCompileResult{
		Approvers: config.Approvers{
			Keys: map[string][]string{
				"IMATCHES": {`HKEY_LOCAL_MACHINE\SOFTWARE\*`},
			},
		},
	}

	a := newTestRegistryApprover(rules)
	r := buildRegOpenKeyRecord(t, 0, `HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.AAC`)

	_, approved := a.Approve(r)
	if !approved {
		t.Error("direct registry path from event should be directly passed to approver")
	}
}
