/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package etw

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

const canary = 0xFF

// newRecord returns an event record whose payload is a copy of the given bytes.
// The payload is surrounded by non-zero canary bytes, so a read that strays past
// either end of the payload picks up the canary instead of silently getting a
// zero, and is therefore visible to the assertions. The returned backing slice
// must be kept alive for as long as the record is in use.
func newRecord(payload []byte) (*EventRecord, []byte) {
	const pad = 64
	backing := make([]byte, pad+len(payload)+pad)
	for i := range backing {
		backing[i] = canary
	}
	copy(backing[pad:], payload)
	return &EventRecord{
		BufferLen: uint16(len(payload)),
		Buffer:    uintptr(unsafe.Pointer(&backing[pad])),
	}, backing
}

func TestReadBuffer(t *testing.T) {
	var tests = []struct {
		buf        []byte
		assertions func(t *testing.T, ev *EventRecord)
	}{
		{
			[]byte{
				0x70, 0x3B, 0xD1, 0x24, 0x8E, 0xD6, 0xFF, 0xFF, 0x9C, 0x02, 0x00, 0x00, 0x2C, 0x00, 0x5C, 0x00,
				0x52, 0x00, 0x45, 0x00, 0x47, 0x00, 0x49, 0x00, 0x53, 0x00, 0x54, 0x00, 0x52, 0x00, 0x59, 0x00,
				0x5C, 0x00, 0x55, 0x00, 0x53, 0x00, 0x45, 0x00, 0x52, 0x00, 0x5C, 0x00, 0x53, 0x00, 0x2D, 0x00,
				0x31, 0x00, 0x2D, 0x00, 0x35, 0x00, 0x2D, 0x00, 0x32, 0x00, 0x31, 0x00, 0x2D, 0x00, 0x32, 0x00,
				0x32, 0x00, 0x37, 0x00, 0x31, 0x00, 0x30, 0x00, 0x33, 0x00, 0x34, 0x00, 0x34, 0x00, 0x35, 0x00,
				0x32, 0x00, 0x2D, 0x00, 0x32, 0x00, 0x36, 0x00, 0x30, 0x00, 0x36, 0x00, 0x32, 0x00, 0x37, 0x00,
				0x30, 0x00, 0x30, 0x00, 0x39, 0x00, 0x39, 0x00, 0x2D, 0x00, 0x39, 0x00, 0x38, 0x00, 0x34, 0x00,
				0x38, 0x00, 0x37, 0x00, 0x31, 0x00, 0x35, 0x00, 0x36, 0x00, 0x39, 0x00, 0x2D, 0x00, 0x31, 0x00,
				0x30, 0x00, 0x30, 0x00, 0x31, 0x00, 0x00, 0x00},
			func(t *testing.T, ev *EventRecord) {
				assert.Equal(t, uint64(18446698504724233072), ev.ReadUint64(0))
				assert.Equal(t, uint64(0), ev.ReadUint64(ev.BufferLen+20))
				assert.Equal(t, uint32(668), ev.ReadUint32(8))
				assert.Equal(t, uint16(44), ev.ReadUint16(12))
				assert.Equal(t, "\\REGISTRY\\USER\\S-1-5-21-2271034452-2606270099-984871569-1001", ev.ConsumeUTF16String(14))
			},
		},
		{
			[]byte{
				0x80, 0xE0, 0x2E, 0x49, 0x06, 0xC1, 0xFF, 0xFF, 0xE8, 0x30, 0x00, 0x00, 0x78, 0x14, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x50, 0x22, 0x91, 0x03, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0xE0, 0x08, 0xE2, 0x1F, 0x0F, 0xA7, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
				0x0F, 0xA7, 0xFF, 0xFF, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00,
				0x63, 0x6D, 0x64, 0x2E, 0x65, 0x78, 0x65, 0x00, 0x43, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x57, 0x00,
				0x49, 0x00, 0x4E, 0x00, 0x44, 0x00, 0x4F, 0x00, 0x57, 0x00, 0x53, 0x00, 0x5C, 0x00, 0x73, 0x00,
				0x79, 0x00, 0x73, 0x00, 0x74, 0x00, 0x65, 0x00, 0x6D, 0x00, 0x33, 0x00, 0x32, 0x00, 0x5C, 0x00,
				0x63, 0x00, 0x6D, 0x00, 0x64, 0x00, 0x2E, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65, 0x00, 0x20, 0x00,
				0x2F, 0x00, 0x63, 0x00, 0x20, 0x00, 0x64, 0x00, 0x69, 0x00, 0x72, 0x00, 0x20, 0x00, 0x2F, 0x00,
				0x2D, 0x00, 0x43, 0x00, 0x20, 0x00, 0x2F, 0x00, 0x57, 0x00, 0x20, 0x00, 0x22, 0x00, 0x5C, 0x00,
				0x5C, 0x00, 0x3F, 0x00, 0x5C, 0x00, 0x63, 0x00, 0x3A, 0x00, 0x5C, 0x00, 0x55, 0x00, 0x73, 0x00,
				0x65, 0x00, 0x72, 0x00, 0x73, 0x00, 0x5C, 0x00, 0x6E, 0x00, 0x65, 0x00, 0x64, 0x00, 0x6F, 0x00,
				0x5C, 0x00, 0x41, 0x00, 0x70, 0x00, 0x70, 0x00, 0x44, 0x00, 0x61, 0x00, 0x74, 0x00, 0x61, 0x00,
				0x5C, 0x00, 0x52, 0x00, 0x6F, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x69, 0x00, 0x6E, 0x00, 0x67, 0x00,
				0x5C, 0x00, 0x52, 0x00, 0x61, 0x00, 0x62, 0x00, 0x62, 0x00, 0x69, 0x00, 0x74, 0x00, 0x4D, 0x00,
				0x51, 0x00, 0x5C, 0x00, 0x64, 0x00, 0x62, 0x00, 0x5C, 0x00, 0x72, 0x00, 0x61, 0x00, 0x62, 0x00,
				0x62, 0x00, 0x69, 0x00, 0x74, 0x00, 0x40, 0x00, 0x61, 0x00, 0x72, 0x00, 0x63, 0x00, 0x68, 0x00,
				0x72, 0x00, 0x61, 0x00, 0x62, 0x00, 0x62, 0x00, 0x69, 0x00, 0x74, 0x00, 0x2D, 0x00, 0x6D, 0x00,
				0x6E, 0x00, 0x65, 0x00, 0x73, 0x00, 0x69, 0x00, 0x61, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00},
			func(t *testing.T, ev *EventRecord) {
				assert.Equal(t, uint32(12520), ev.ReadUint32(8))
				assert.Equal(t, uint32(5240), ev.ReadUint32(12))

				rawSid, offset := ev.ReadSID(36, true)
				b := uintptr(unsafe.Pointer(&rawSid[0]))
				b += uintptr(8 * 2)

				sid := (*windows.SID)(unsafe.Pointer(b))
				assert.Equal(t, "S-1-5-18", sid.String())

				name, noffset := ev.ReadAnsiString(offset)
				assert.Equal(t, "cmd.exe", name)
				cmdline, _ := ev.ReadUTF16String(noffset)
				assert.Equal(t, "C:\\WINDOWS\\system32\\cmd.exe /c dir /-C /W \"\\\\?\\c:\\Users\\nedo\\AppData\\Roaming\\RabbitMQ\\db\\rabbit@archrabbit-mnesia\"", cmdline)
			},
		},
	}

	for _, tt := range tests {
		ev := &EventRecord{
			BufferLen: uint16(len(tt.buf)),
			Buffer:    uintptr(unsafe.Pointer(&tt.buf[0])),
		}
		tt.assertions(t, ev)
	}
}

func TestReadFixedSizeOutOfBounds(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ev, backing := newRecord(payload)
	defer runtime.KeepAlive(backing)

	assert.Equal(t, byte(8), ev.ReadByte(7))
	assert.Equal(t, byte(0), ev.ReadByte(8), "offset == BufferLen is one past the end")
	assert.Equal(t, byte(0), ev.ReadByte(65535))

	assert.Equal(t, uint16(0x0201), ev.ReadUint16(0))
	assert.Equal(t, uint16(0), ev.ReadUint16(7), "value straddles the end of the buffer")
	assert.Equal(t, uint16(0), ev.ReadUint16(65535))

	assert.Equal(t, uint32(0x04030201), ev.ReadUint32(0))
	assert.Equal(t, uint32(0), ev.ReadUint32(5), "value straddles the end of the buffer")
	assert.Equal(t, uint32(0), ev.ReadUint32(65534))

	assert.Equal(t, uint64(0x0807060504030201), ev.ReadUint64(0))
	assert.Equal(t, uint64(0), ev.ReadUint64(1), "value straddles the end of the buffer")
	assert.Equal(t, uint64(0), ev.ReadUint64(65530))

	assert.Equal(t, []byte{3, 4}, ev.ReadBytes(2, 2))
	assert.Equal(t, []byte{7, 8}, ev.ReadBytes(6, 2))
	assert.Len(t, ev.ReadBytes(8, 0), 0)
	assert.Nil(t, ev.ReadBytes(4, 8), "range extends past the end of the buffer")
	assert.Nil(t, ev.ReadBytes(65535, 65535), "offset + count must not wrap around uint16")

	// the returned view must not let callers append into adjacent memory
	b := ev.ReadBytes(0, 2)
	assert.Equal(t, 2, cap(b))
}

func TestReadEmptyAndDetachedBuffers(t *testing.T) {
	for _, ev := range []*EventRecord{
		{},                        // no payload at all
		{BufferLen: 16},           // length without a pointer
		{Buffer: 0xdeadbeef},      // pointer without a length
		{BufferLen: 0, Buffer: 1}, // zero-length payload
	} {
		assert.NotPanics(t, func() {
			assert.Equal(t, byte(0), ev.ReadByte(0))
			assert.Equal(t, uint64(0), ev.ReadUint64(0))
			assert.Nil(t, ev.ReadBytes(0, 4))
			s, _ := ev.ReadAnsiString(0)
			assert.Equal(t, "", s)
			s, _ = ev.ReadUTF16String(0)
			assert.Equal(t, "", s)
			s, _ = ev.ReadNTUnicodeString(0)
			assert.Equal(t, "", s)
			assert.Equal(t, "", ev.ConsumeUTF16String(0))
			assert.Nil(t, ev.ConsumeRawUTF16String(0))
			sid, _ := ev.ReadSID(0, false)
			assert.Nil(t, sid)
			assert.Len(t, ev.ReadCallstack(0), 0)
		})
	}
}

func TestReadAnsiString(t *testing.T) {
	// terminated string followed by a second one
	ev, backing := newRecord([]byte{'c', 'm', 'd', 0, 'x', 0})
	defer runtime.KeepAlive(backing)

	s, next := ev.ReadAnsiString(0)
	assert.Equal(t, "cmd", s)
	assert.Equal(t, uint16(4), next)

	s, next = ev.ReadAnsiString(next)
	assert.Equal(t, "x", s)
	assert.Equal(t, uint16(6), next)

	// empty string consumes only the terminator
	ev, backing = newRecord([]byte{0, 'a', 0})
	defer runtime.KeepAlive(backing)
	s, next = ev.ReadAnsiString(0)
	assert.Equal(t, "", s)
	assert.Equal(t, uint16(1), next)

	// unterminated string must stop at the end of the buffer instead of
	// running into the adjacent memory, regardless of the starting offset
	ev, backing = newRecord([]byte{'a', 'b', 'c'})
	defer runtime.KeepAlive(backing)
	s, next = ev.ReadAnsiString(0)
	assert.Equal(t, "abc", s)
	assert.Equal(t, uint16(3), next)
	s, next = ev.ReadAnsiString(2)
	assert.Equal(t, "c", s)
	assert.Equal(t, uint16(3), next)

	// out of range offsets fail closed: the returned offset is the end of the
	// buffer, so chained reads don't wrap around to the start of the payload
	s, next = ev.ReadAnsiString(3)
	assert.Equal(t, "", s)
	assert.Equal(t, uint16(3), next)
	s, next = ev.ReadAnsiString(65535)
	assert.Equal(t, "", s)
	assert.Equal(t, uint16(3), next)
}

func TestReadUTF16String(t *testing.T) {
	// "ab\0" "c\0"
	ev, backing := newRecord([]byte{'a', 0, 'b', 0, 0, 0, 'c', 0, 0, 0})
	defer runtime.KeepAlive(backing)

	s, next := ev.ReadUTF16String(0)
	assert.Equal(t, "ab", s)
	assert.Equal(t, uint16(6), next)

	s, next = ev.ReadUTF16String(next)
	assert.Equal(t, "c", s)
	assert.Equal(t, uint16(10), next)

	// empty string consumes only the terminator
	ev, backing = newRecord([]byte{0, 0, 'a', 0})
	defer runtime.KeepAlive(backing)
	s, next = ev.ReadUTF16String(0)
	assert.Equal(t, "", s)
	assert.Equal(t, uint16(2), next)

	// unterminated string with a dangling odd byte must stop at the end of the buffer
	ev, backing = newRecord([]byte{'a', 0, 'b', 0, 'c'})
	defer runtime.KeepAlive(backing)
	s, next = ev.ReadUTF16String(0)
	assert.Equal(t, "ab", s)
	assert.Equal(t, uint16(5), next)

	// out of range offsets, including a single trailing byte
	s, next = ev.ReadUTF16String(4)
	assert.Equal(t, "", s)
	assert.Equal(t, uint16(5), next)
	s, next = ev.ReadUTF16String(65535)
	assert.Equal(t, "", s)
	assert.Equal(t, uint16(5), next)
}

func TestReadNTUnicodeString(t *testing.T) {
	ev, backing := newRecord([]byte{'e', 0, 'x', 0, 'e', 0, 0, 0})
	defer runtime.KeepAlive(backing)

	s, next := ev.ReadNTUnicodeString(0)
	assert.Equal(t, "exe", s)
	assert.Equal(t, uint16(6), next)

	// unterminated, odd length
	ev, backing = newRecord([]byte{'e', 0, 'x', 0, 'e'})
	defer runtime.KeepAlive(backing)
	s, next = ev.ReadNTUnicodeString(0)
	assert.Equal(t, "ex", s)
	assert.Equal(t, uint16(4), next)

	s, next = ev.ReadNTUnicodeString(5)
	assert.Equal(t, "", s)
	assert.Equal(t, uint16(5), next)
}

func TestConsumeUTF16String(t *testing.T) {
	ev, backing := newRecord([]byte{'a', 0, 'b', 0, 0, 0})
	defer runtime.KeepAlive(backing)

	assert.Equal(t, "ab", ev.ConsumeUTF16String(0))
	assert.Equal(t, "b", ev.ConsumeUTF16String(2))
	assert.Equal(t, "", ev.ConsumeUTF16String(4), "only the terminator is left")

	// nothing or less than a code unit left: used to underflow the slice bounds
	assert.NotPanics(t, func() {
		assert.Equal(t, "", ev.ConsumeUTF16String(5))
		assert.Equal(t, "", ev.ConsumeUTF16String(6))
		assert.Equal(t, "", ev.ConsumeUTF16String(65535))
	})

	// the raw variant must hold exactly the number of code units that fit
	// into the buffer. It used to claim twice as many, which made any
	// consumer iterating over it read past the end of the event
	assert.Len(t, ev.ConsumeRawUTF16String(0), 3)
	assert.Len(t, ev.ConsumeRawUTF16String(1), 2, "odd trailing byte is ignored")
	assert.Len(t, ev.ConsumeRawUTF16String(4), 1)
	assert.Nil(t, ev.ConsumeRawUTF16String(5))
	assert.Nil(t, ev.ConsumeRawUTF16String(6))
	assert.Nil(t, ev.ConsumeRawUTF16String(65535))

	raw := ev.ConsumeRawUTF16String(0)
	assert.Equal(t, []uint16{'a', 'b', 0}, raw)
	assert.Equal(t, 3, cap(raw))
}

func TestReadSIDBounds(t *testing.T) {
	// S-1-5-18 (local system), a single sub-authority
	system := []byte{0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00}

	ev, backing := newRecord(system)
	defer runtime.KeepAlive(backing)
	sid, next := ev.ReadSID(0, false)
	assert.Equal(t, system, sid)
	assert.Equal(t, uint16(12), next)

	// a null security token takes 4 bytes and has no SID
	ev, backing = newRecord([]byte{0, 0, 0, 0, 0xAA})
	defer runtime.KeepAlive(backing)
	sid, next = ev.ReadSID(0, false)
	assert.Nil(t, sid)
	assert.Equal(t, uint16(4), next)

	// the sub-authority count claims far more data than the buffer holds
	ev, backing = newRecord([]byte{0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05})
	defer runtime.KeepAlive(backing)
	sid, next = ev.ReadSID(0, false)
	assert.Nil(t, sid)
	assert.Equal(t, uint16(8), next)

	// SID is cut off right after the count
	ev, backing = newRecord([]byte{0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00})
	defer runtime.KeepAlive(backing)
	sid, _ = ev.ReadSID(0, false)
	assert.Nil(t, sid, "two sub-authorities need 16 bytes")

	// the count lives past the end of the buffer
	assert.NotPanics(t, func() {
		sid, next = ev.ReadSID(10, true)
		assert.Nil(t, sid)
		sid, next = ev.ReadSID(65535, true)
		assert.Nil(t, sid)
		assert.Equal(t, uint16(12), next)
	})

	// WBEM SIDs are prefixed by a 16 byte token
	wbem := append(make([]byte, 16), system...)
	wbem[0] = 0x01 // non-null token
	ev, backing = newRecord(wbem)
	defer runtime.KeepAlive(backing)
	sid, next = ev.ReadSID(0, true)
	assert.Equal(t, wbem, sid)
	assert.Equal(t, uint16(28), next)
}

func TestReadCallstackBounds(t *testing.T) {
	payload := []byte{
		1, 0, 0, 0, 0, 0, 0, 0,
		2, 0, 0, 0, 0, 0, 0, 0,
		0xAA, 0xBB, 0xCC, // dangling bytes, not a full frame
	}
	ev, backing := newRecord(payload)
	defer runtime.KeepAlive(backing)

	assert.Equal(t, []va.Address{1, 2}, ev.ReadCallstack(0))
	assert.Equal(t, []va.Address{2}, ev.ReadCallstack(8))
	assert.Len(t, ev.ReadCallstack(16), 0)

	// offsets past the end used to underflow the frame count
	assert.NotPanics(t, func() {
		assert.Len(t, ev.ReadCallstack(19), 0)
		assert.Len(t, ev.ReadCallstack(20), 0)
		assert.Len(t, ev.ReadCallstack(65535), 0)
	})

	// reusing a callstack must start from scratch and keep its backing array
	cs := make(va.Callstack, 0, 8)
	cs = append(cs, 9, 9, 9)
	got := ev.ReadCallstackInto(0, cs)
	assert.Equal(t, []va.Address{1, 2}, got)
	assert.Equal(t, 8, cap(got))

	// the result must be a copy, not a view over the event payload
	got[0] = 0xDEAD
	assert.Equal(t, uint64(1), ev.ReadUint64(0))
	assert.Equal(t, []va.Address{1, 2}, ev.ReadCallstack(0))

	// a callstack with too little capacity is grown
	small := make(va.Callstack, 0, 1)
	assert.Equal(t, []va.Address{1, 2}, ev.ReadCallstackInto(0, small))
}

func TestCloneEmptyPayload(t *testing.T) {
	assert.NotPanics(t, func() {
		c, buf := (&EventRecord{}).Clone()
		assert.Equal(t, uintptr(0), c.Buffer)
		assert.Len(t, buf, 0)
	})

	ev, backing := newRecord([]byte{1, 2, 3, 4})
	defer runtime.KeepAlive(backing)
	c, buf := ev.Clone()
	assert.Equal(t, []byte{1, 2, 3, 4}, buf)
	assert.Equal(t, uint32(0x04030201), c.ReadUint32(0))
	assert.Equal(t, true, c.Buffer != ev.Buffer, "the clone must not alias the original payload")
}

func TestExtendedDataBounds(t *testing.T) {
	// the event claims extended data items, but has no storage for them
	ev := &EventRecord{ExtendedDataCount: 2}
	assert.NotPanics(t, func() {
		assert.Equal(t, false, ev.HasStackTrace())
		assert.Nil(t, ev.Callstack())
		assert.Nil(t, ev.ReadEventHeaderFileExtendedDataItemsCallstack())
		d, s := ev.ReadEventHeaderFileExtendedDataItems()
		assert.Equal(t, uint32(0), d)
		assert.Equal(t, uint32(0), s)
	})

	// stack trace item: match id followed by two return addresses
	stack := []uint64{0xCAFE, 0x1000, 0x2000}
	defer runtime.KeepAlive(stack)
	item := EventHeaderExtendedDataItem{
		ExtType:  EventHeaderExtTypeStackTrace64,
		DataSize: uint16(len(stack) * 8),
		DataPtr:  uint64(uintptr(unsafe.Pointer(&stack[0]))),
	}
	ev = &EventRecord{ExtendedDataCount: 1, ExtendedData: &item}
	assert.Equal(t, true, ev.HasStackTrace())
	assert.Equal(t, []va.Address{0x1000, 0x2000}, ev.Callstack())

	// a stack trace item that is smaller than its match id is malformed. The
	// frame count used to be computed as (DataSize-8)/8 on a uint16, which
	// wrapped around and read ~64KB beyond the item
	for _, size := range []uint16{0, 4, 7} {
		bad := item
		bad.DataSize = size
		ev = &EventRecord{ExtendedDataCount: 1, ExtendedData: &bad}
		assert.NotPanics(t, func() { assert.Nil(t, ev.Callstack(), "size %d", size) })
	}

	// no return addresses, only the match id
	empty := item
	empty.DataSize = 8
	ev = &EventRecord{ExtendedDataCount: 1, ExtendedData: &empty}
	assert.Len(t, ev.Callstack(), 0)

	// null data pointers
	null := item
	null.DataPtr = 0
	ev = &EventRecord{ExtendedDataCount: 1, ExtendedData: &null}
	assert.NotPanics(t, func() { assert.Nil(t, ev.Callstack()) })

	// custom file extended data items
	callstack := []va.Address{0x1000, 0x2000, 0x3000}
	ev = &EventRecord{}
	f := AppendEventHeaderFileExtendedDataItems(ev, 2, 0xC0000022, callstack)
	assert.Equal(t, callstack, ev.ReadEventHeaderFileExtendedDataItemsCallstack())
	disposition, status := ev.ReadEventHeaderFileExtendedDataItems()
	assert.Equal(t, uint32(2), disposition)
	assert.Equal(t, uint32(0xC0000022), status)
	runtime.KeepAlive(f)

	// callstack item pointing nowhere
	f.items[2].DataPtr = 0
	ev.ExtendedData, ev.ExtendedDataCount = &f.items[2], 1
	assert.NotPanics(t, func() { assert.Nil(t, ev.ReadEventHeaderFileExtendedDataItemsCallstack()) })
}

func TestClassicEventIDIsEmpty(t *testing.T) {
	guid := windows.GUID{Data1: 0x3d6fa8d0, Data2: 0xfe05, Data3: 0x11d0, Data4: [8]byte{0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}}

	assert.Equal(t, true, ClassicEventID{}.IsEmpty())
	assert.Equal(t, true, ClassicEventID{GUID: guid}.IsEmpty(), "no type")
	assert.Equal(t, true, ClassicEventID{Type: 1}.IsEmpty(), "no GUID")
	assert.Equal(t, true, ClassicEventID{GUID: windows.GUID{Data4: [8]byte{0, 0, 0, 0, 0, 0, 0, 0}}, Type: 1}.IsEmpty())
	assert.Equal(t, false, NewClassicEventID(guid, 1).IsEmpty())
	// a GUID that is zero except for the trailing bytes is still a GUID
	assert.Equal(t, false, ClassicEventID{GUID: windows.GUID{Data4: [8]byte{0, 0, 0, 0, 0, 0, 0, 1}}, Type: 1}.IsEmpty())
}
