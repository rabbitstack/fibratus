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

package event

import (
	"errors"
	"fmt"
	"sync"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/filetime"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
)

// ErrShortBuffer is reported when a read would go past the end of the
// event buffer. It is sticky. Once set, every subsequent read is a no-op
// that returns the zero value, so callers can check Err() once at the end.
var ErrShortBuffer = errors.New("event buffer too short")

// Cursor tracks the read position inside a raw event buffer and advances
// it as fields are consumed.
type Cursor struct {
	r    *etw.EventRecord
	off  uint16
	size uint16 // total length of the user data buffer
	err  error

	v6 bool // address family of the current network record
}

// NewCursor returns a cursor positioned at offset 0.
// size is the length of the event's user data.
func NewCursor(r *etw.EventRecord, size uint16) *Cursor {
	return &Cursor{r: r, size: size}
}

// Reset rewinds the cursor and rebinds it to a new reader so a single
// Cursor can be pooled and reused across events without allocating.
func (c *Cursor) Reset(r *etw.EventRecord, size uint16) {
	c.r, c.off, c.size, c.err, c.v6 = r, 0, size, nil, false
}

// Offset returns the current position.
func (c *Cursor) Offset() uint16 { return c.off }

// Remaining returns how many bytes are left in the buffer.
func (c *Cursor) Remaining() uint16 { return c.size - c.off }

// Err returns the first error encountered, if any.
func (c *Cursor) Err() error { return c.err }

// Seek moves the cursor to an absolute offset.
func (c *Cursor) Seek(off uint16) {
	if off > c.size {
		c.fail()
		return
	}
	c.off = off
}

// need reports whether n more bytes are available, flagging the cursor
// as failed otherwise.
func (c *Cursor) need(n uint16) bool {
	if c.err != nil {
		return false
	}
	if n > c.size-c.off {
		c.err = ErrShortBuffer
		return false
	}
	return true
}

func (c *Cursor) fail() {
	if c.err == nil {
		c.err = ErrShortBuffer
	}
}

// Skip advances over n bytes (reserved fields, padding).
func (c *Cursor) Skip(n uint16) {
	if c.need(n) {
		c.off += n
	}
}

// Align advances to the next multiple of n (n must be a power of two).
func (c *Cursor) Align(n uint16) {
	if n <= 1 {
		return
	}
	c.Skip((n - c.off&(n-1)) & (n - 1))
}

func (c *Cursor) U8() uint8 {
	if !c.need(1) {
		return 0
	}
	v := c.r.ReadByte(c.off)
	c.off++
	return v
}

func (c *Cursor) U16() uint16 {
	if !c.need(2) {
		return 0
	}
	v := c.r.ReadUint16(c.off)
	c.off += 2
	return v
}

func (c *Cursor) U32() uint32 {
	if !c.need(4) {
		return 0
	}
	v := c.r.ReadUint32(c.off)
	c.off += 4
	return v
}

func (c *Cursor) U64() uint64 {
	if !c.need(8) {
		return 0
	}
	v := c.r.ReadUint64(c.off)
	c.off += 8
	return v
}

// Ansi reads a NUL-terminated ANSI string.
func (c *Cursor) Ansi() string {
	if !c.need(1) {
		return ""
	}
	s, next := c.r.ReadAnsiString(c.off)
	return c.advanceTo(next, s)
}

// UTF16 reads a NUL-terminated UTF-16 string.
func (c *Cursor) UTF16() string {
	if !c.need(2) {
		return ""
	}
	s, next := c.r.ReadUTF16String(c.off)
	return c.advanceTo(next, s)
}

// UTF16 reads a NUL-terminated UTF-16 trailer string.
func (c *Cursor) UTF16Trailer() string {
	if !c.need(2) {
		return ""
	}
	s := c.r.ConsumeUTF16String(c.off)
	c.off = c.size
	return s
}

// NTUnicode reads a UTF-16 string for NT native APIs.
func (c *Cursor) NTUnicode() string {
	if !c.need(2) {
		return ""
	}
	s, next := c.r.ReadNTUnicodeString(c.off)
	return c.advanceTo(next, s)
}

// SID reads a variable length SID (TOKEN_USER prefixed when tokenUser is true).
func (c *Cursor) SID(tokenUser bool) []byte {
	if !c.need(1) {
		return nil
	}
	sid, next := c.r.ReadSID(c.off, tokenUser)
	if next < c.off || next > c.size {
		c.fail()
		return nil
	}
	c.off = next
	return sid
}

// Bytes reads the next n bytes. The result is a copy, so it stays valid
// after the callback returns.
func (c *Cursor) Bytes(n uint16) []byte {
	if !c.need(n) {
		return nil
	}
	b := make([]byte, n)
	copy(b, c.r.ReadBytes(c.off, n))
	c.off += n
	return b
}

// BytesU16 reads a uint16 length followed by that many bytes.
// The result is a copy, so it is safe to keep after the callback returns.
func (c *Cursor) BytesU16() []byte {
	n := c.U16()
	if c.err != nil || n == 0 {
		return nil
	}
	return c.Bytes(n)
}

// Addresses reads the return addresses and reuses the slice from the pooled callstack.
func (c *Cursor) Addresses(v va.Callstack) []va.Address {
	if c.err != nil {
		return nil
	}
	addrs := c.r.ReadCallstackInto(c.off, v)
	n := len(addrs) * 8
	if n > int(c.Remaining()) {
		c.fail()
		return nil
	}
	c.off += uint16(n)
	return addrs
}

func (c *Cursor) advanceTo(next uint16, s string) string {
	if next < c.off || next > c.size {
		c.fail()
		return ""
	}
	c.off = next
	return s
}

// Release drops the reference to the record so a pooled cursor does not
// keep the event buffer alive.
func (c *Cursor) Release() {
	c.r, c.off, c.size, c.err = nil, 0, 0, nil
}

// ParamDecoder parses parameters from the event buffer.
type ParamDecoder struct {
	cur Cursor
}

var decoderPool = sync.Pool{
	New: func() any { return new(ParamDecoder) },
}

// AcquireDecoder borrows a decoder from the pool.
func AcquireDecoder() *ParamDecoder {
	return decoderPool.Get().(*ParamDecoder)
}

// Release resets the cursor state.
func (d *ParamDecoder) Release() { d.cur.Release() }

// ReleaseDecoder returns a decoder to the pool. The decoder must not be
// used afterwards.
func ReleaseDecoder(d *ParamDecoder) {
	d.Release()
	decoderPool.Put(d)
}

// Decode reads the event parameter schema and drives the encoding
// with the cursor-based buffer position tracking.
func (d *ParamDecoder) Decode(r *etw.EventRecord, e *Event) error {
	if e.Type == Unknown || int(e.Type) >= len(table) {
		return errors.New("invalid event type")
	}

	info := table[e.Type]
	if len(info.Params) == 0 {
		return fmt.Errorf("parameters schema not defined for event type %s", e.Type)
	}

	d.cur.Reset(r, r.BufferLen)
	d.cur.v6 = isIPv6(r.Header.EventDescriptor.Opcode)

	for i, p := range info.Params {
		switch p.WireFormat {
		case params.WireNone:
			if p.FromRecord != nil {
				e.Params.Set(i, p.FromRecord(r))
			}
			continue
		case params.WireSkip:
			d.cur.Skip(p.Size)
		case params.WireU8:
			e.Params.Set(i, params.U32(uint32(d.cur.U8())))
		case params.WireU16:
			e.Params.Set(i, params.U32(uint32(d.cur.U16())))
		case params.WireU32:
			e.Params.Set(i, params.U32(d.cur.U32()))
		case params.WireU64:
			e.Params.Set(i, params.U64(d.cur.U64()))
		case params.WireU32Bool:
			e.Params.Set(i, params.Boolean(d.cur.U32() > 0))
		case params.WireAnsi:
			e.Params.Set(i, params.Str(d.cur.Ansi()))
		case params.WireUTF16:
			s := d.cur.UTF16()
			if p.Sanitize != nil {
				e.Params.Set(i, p.Sanitize(s))
			} else {
				e.Params.Set(i, params.Str(s))
			}
		case params.WireUTF16Trailer:
			e.Params.Set(i, params.Str(d.cur.UTF16Trailer()))
		case params.WireNTUnicode:
			e.Params.Set(i, params.Str(d.cur.NTUnicode()))
		case params.WireSID, params.WireWbemSID:
			e.Params.Set(i, params.Bin(d.cur.SID(p.WireFormat == params.WireWbemSID)))
		case params.WireBytes:
			e.Params.Set(i, params.Bin(d.cur.Bytes(p.Size)))
		case params.WireBytesU16:
			buf := d.cur.BytesU16()
			e.SetParam(p.Name, params.Bin(buf))
			if p.Interpret == nil {
				break
			}
			v := p.Interpret(e.GetParamAsUint32(p.Selector), buf)
			i := e.Params.Index(p.Into)
			if i < 0 {
				i = e.Params.Index(p.Name)
			}
			e.Params.Set(i, v)
		case params.WireIP:
			if d.cur.v6 {
				e.Params.Set(i, params.IP6(d.cur.Bytes(16)))
				break
			}
			e.Params.Set(i, params.IPv4LE(d.cur.U32()))
		case params.WirePort:
			e.Params.Set(i, params.U16(windows.Ntohs(d.cur.U16())))
		case params.WireFileTime:
			ft := windows.NsecToFiletime(int64(d.cur.U64()))
			e.Params.Set(i, params.Timestamp(filetime.ToEpoch(uint64(ft.Nanoseconds()))))
		case params.WireAddrs:
			e.Params.Set(i, params.Addresses(d.cur.Addresses(va.GetCallstack())))
		case params.WireU32Bits:
			v := d.cur.U32()
			e.Params.Set(i, params.U32(v))
			l := e.Params.Len()
			for j, derive := range p.Derives {
				e.Params.Set(l+j, params.U32(derive.ExtractU32(v)))
			}
		case params.WireU64Bits:
			v := d.cur.U64()
			e.Params.Set(i, params.U64(v))
			l := e.Params.Len()
			for j, derive := range p.Derives {
				e.Params.Set(l+j, params.U32(derive.ExtractU64(v)))
			}
		}
		if d.cur.Err() != nil {
			return d.cur.Err()
		}
	}
	return nil
}

func isIPv6(opcode uint8) bool {
	return opcode == AcceptTCPv6ID || opcode == ConnectTCPv6ID || opcode == ReconnectTCPv6ID || opcode == RetransmitTCPv6ID ||
		opcode == DisconnectTCPv6ID || opcode == SendV6ID || opcode == RecvV6ID
}
