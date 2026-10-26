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
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/filetime"
	"github.com/rabbitstack/fibratus/pkg/util/utf16"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ErrShortBuffer is reported when a read would go past the end of the
// event buffer. It is sticky. Once set, every subsequent read is a no-op
// that returns the zero value, so callers can check Err() once at the end.
var ErrShortBuffer = errors.New("event buffer too short")

// RecordReader is the set of offset-based primitives the cursor needs.
type RecordReader interface {
	ReadByte(off uint16) uint8
	ReadUint16(off uint16) uint16
	ReadUint32(off uint16) uint32
	ReadUint64(off uint16) uint64
	ReadAnsiString(off uint16) (string, uint16)
	ReadUTF16String(off uint16) (string, uint16)
	ReadNTUnicodeString(off uint16) (string, uint16)
	ReadSID(off uint16, tokenUser bool) ([]byte, uint16)
	ReadBytes(off uint16, count uint16) []byte
}

// Cursor tracks the read position inside a raw event buffer and advances
// it as fields are consumed. It wraps the existing Reader so the offset-based
// primitives (ReadUint32, ReadUTF16String, and so on) stay the single source
// of truth for how bytes are interpreted.
type Cursor struct {
	r    RecordReader
	off  uint16
	size uint16 // total length of the user data buffer
	err  error

	v6 bool // address family of the current record
}

// NewCursor returns a cursor positioned at offset 0.
// size is the length of the event's user data.
func NewCursor(r RecordReader, size uint16) *Cursor {
	return &Cursor{r: r, size: size}
}

// Reset rewinds the cursor and rebinds it to a new reader so a single
// Cursor can be pooled and reused across events without allocating.
func (c *Cursor) Reset(r RecordReader, size uint16) {
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
	if c.off+n > c.size {
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
			n := d.cur.U32()
			if p.BitField != nil {
				n = p.BitField.Extract(n)
			}
			e.Params.Set(i, params.U32(n))
		case params.WireU64:
			e.Params.Set(i, params.U64(d.cur.U64()))
		case params.WireU32Bool:
			e.Params.Set(i, params.Boolean(d.cur.U32() > 0))
		case params.WireAnsi:
			e.Params.Set(i, params.Str(d.cur.Ansi()))
		case params.WireUTF16:
			e.Params.Set(i, params.Str(d.cur.UTF16()))
		case params.WireNTUnicode:
			e.Params.Set(i, params.Str(d.cur.NTUnicode()))
		case params.WireSID, params.WireWbemSID:
			e.Params.Set(i, params.Bin(d.cur.SID(p.WireFormat == params.WireWbemSID)))
		case params.WireBytes:
			e.Params.Set(i, params.Bin(d.cur.Bytes(p.Size)))
		case params.WireBytesU16:
			buf := d.cur.BytesU16()
			e.SetParam(p.Name, params.Bin(buf))
			if p.Interpret == nil || p.Into == "" {
				break
			}
			v := p.Interpret(e.GetParamAsUint32(p.Selector), buf)
			e.SetParam(p.Into, v)
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
			addrs := r.ReadCallstackInto(d.cur.off, va.GetCallstack())
			e.Params.Set(i, params.Addresses(addrs))
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

// DecodeRegistry parses registry events such as key creation,
// key/value access, or value mutation.
func (d *ParamDecoder) DecodeRegistry(r *etw.EventRecord, e *Event) {
	//	typedef struct _WMI_REGISTRY {
	//	    LONGLONG InitialTime;
	//	    ULONG Status;
	//	    union{
	//	        ULONG Index;
	//	        ULONG InfoClass;
	//	    } DUMMYUNIONNAME;
	//	    PVOID Kcb;
	//	    WCHAR Name[1];
	//	} WMI_REGISTRY, *PWMI_REGISTRY;

	// skip InitialTime (uint64)
	e.SetParam(params.NTStatus, params.U32(r.ReadUint32(8)))
	// skip Index/InfoClass (uint32)
	e.SetParam(params.RegKCB, params.U64(r.ReadUint64(16)))
	e.SetParam(params.RegPath, params.Str(r.ConsumeUTF16String(24)))
}

// DecodeRegSetValueInternal decodes the payload for the registry set value
// event used for enriching the core RegSetValue event emitted by the system
// logger.
//
// The event describes a registry value modification operation and contains
// both metadata about the target registry value and a captured snapshot of
// the written data buffer.
func (d *ParamDecoder) DecodeRegSetValueInternal(r *etw.EventRecord, e *Event) {
	// <template tid="task_0SetValueKeyArgs">
	//    <data name="KeyObject" inType="win:Pointer" />
	//    <data name="Status" inType="win:UInt32" />
	//    <data name="Type" inType="win:UInt32" />
	//    <data name="DataSize" inType="win:UInt32" />
	//    <data name="KeyName" inType="win:UnicodeString" />
	//    <data name="ValueName" inType="win:UnicodeString" />
	//    <data name="CapturedDataSize" inType="win:UInt16" />
	//    <data name="CapturedData" inType="win:Binary" length="CapturedDataSize" />
	//    <data name="PreviousDataType" inType="win:UInt32" />
	//    <data name="PreviousDataSize" inType="win:UInt32" />
	//    <data name="PreviousDataCapturedSize" inType="win:UInt16" />
	//    <data name="PreviousData" inType="win:Binary" length="PreviousDataCapturedSize" />
	// </template>
	valueType := r.ReadUint32(12)
	// skip DataSize (uint32)
	keyName, koffset := r.ReadUTF16String(20)
	valueName, voffset := r.ReadUTF16String(koffset)
	capturedSize := r.ReadUint16(voffset)
	capturedData := r.ReadBytes(2+voffset, capturedSize)

	// copy the buffer to avoid dangling pointers
	// after the callback function returns and the
	// buffer lifetime evicts
	b := make([]byte, capturedSize)
	copy(b, capturedData)

	e.SetParam(params.RegKeyHandle, params.U64(r.ReadUint64(0)))
	e.SetParam(params.NTStatus, params.U32(r.ReadUint32(8)))
	e.SetParam(params.RegPath, params.Str(filepath.Join(keyName, valueName)))
	e.SetParam(params.RegValueType, params.U32(valueType))

	if len(b) == 0 {
		return
	}

	// populate value data depending on its type
	switch valueType {
	case registry.SZ, registry.MULTI_SZ, registry.EXPAND_SZ:
		e.SetParam(params.RegData, params.Str(utf16.BytesToString(b, binary.LittleEndian)))
	case registry.BINARY:
		e.SetParam(params.RegData, params.Bin(b))
	case registry.DWORD:
		var v uint32
		switch len(b) {
		case 4:
			v = binary.LittleEndian.Uint32(b)
		case 2:
			v = uint32(binary.LittleEndian.Uint16(b))
		case 1:
			v = uint32(b[0])
		}
		e.SetParam(params.RegData, params.U32(v))
	case registry.DWORD_BIG_ENDIAN:
		var v uint32
		switch len(b) {
		case 4:
			v = binary.BigEndian.Uint32(b)
		case 2:
			v = uint32(binary.BigEndian.Uint16(b))
		case 1:
			v = uint32(b[0])
		}
		e.SetParam(params.RegData, params.U32(v))
	case registry.QWORD:
		var v uint64
		switch len(b) {
		case 8:
			v = binary.LittleEndian.Uint64(b)
		case 4:
			v = uint64(binary.LittleEndian.Uint32(b))
		case 2:
			v = uint64(binary.LittleEndian.Uint16(b))
		case 1:
			v = uint64(b[0])
		}
		e.SetParam(params.RegData, params.U64(v))
	}
}

// DecodeFile decodes file I/O operations such as file creation, access,
// or file metadata manipulation.
func (d *ParamDecoder) DecodeFile(r *etw.EventRecord, e *Event) {
	switch e.Type {
	case CreateFile:
		// typedef struct _PERFINFO_FILE_CREATE {
		//     LONG_PTR Irp;
		//     ULONG_PTR FileObject;
		//     ULONG IssuingThreadId;
		//     ULONG Options;
		//     ULONG Attributes;
		//     ULONG ShareAccess;
		//     WCHAR OpenPath[1];
		// } PERFINFO_FILE_CREATE, *PPERFINFO_FILE_CREATE;
		e.SetParam(params.FileIrpPtr, params.U64(r.ReadUint64(0)))
		e.SetParam(params.FileObject, params.U64(r.ReadUint64(8)))
		e.SetParam(params.ThreadID, params.U32(r.ReadUint32(16)))
		e.SetParam(params.FileCreateOptions, params.U32(r.ReadUint32(20)))
		e.SetParam(params.FileAttributes, params.U32(r.ReadUint32(24)))
		e.SetParam(params.FileShareMask, params.U32(r.ReadUint32(28)))
		e.SetParam(params.FilePath, params.Str(r.ConsumeUTF16String(32)))

		// read create disposition, status, and callstack from extended data items
		disposition, status := r.ReadEventHeaderFileExtendedDataItems()
		e.SetParam(params.NTStatus, params.U32(status))
		e.SetParam(params.FileOperation, params.U32(disposition))
		//e.SetParam(params.Callstack, Addresses(r.ReadEventHeaderFileExtendedDataItemsCallstack()))
	case FileOpEnd:
		// typedef struct _PERFINFO_FILE_OPERATION_END {
		//     ULONG_PTR Irp;
		//     ULONG_PTR ExtraInformation;
		//     NTSTATUS Status;
		// } PERFINFO_FILE_OPERATION_END, *PPERFINFO_FILE_OPERATION_END;
		e.SetParam(params.FileIrpPtr, params.U64(r.ReadUint64(0)))
		e.SetParam(params.FileExtraInfo, params.U64(r.ReadUint64(8)))
		e.SetParam(params.NTStatus, params.U32(r.ReadUint32(16)))
	case MapViewOfSection, UnmapViewOfSection, MapViewSectionRundown:
		e.SetParam(params.FileViewBase, params.U64(r.ReadUint64(0)))
		e.SetParam(params.FileKey, params.U64(r.ReadUint64(8)))
		e.SetParam(params.MemProtect, params.U32(uint32(r.ReadUint64(16)>>32)))
		e.SetParam(params.FileViewSectionType, params.U32(uint32(r.ReadUint64(16)>>52)))
		e.SetParam(params.FileViewSize, params.U64(r.ReadUint64(24)))
		e.SetParam(params.FileOffset, params.U64(r.ReadUint64(32)))
		e.SetParam(params.ProcessID, params.U32(r.ReadUint32(40)))
	case SetFileInformation, DeleteFile, RenameFile:
		// DeleteFile, RenameFile, and SetFileInformation share the same layout
		// typedef struct _PERFINFO_FILE_INFORMATION {
		//     ULONG_PTR Irp;
		//     ULONG_PTR FileObject;
		//     ULONG_PTR FileKey;
		//     ULONG_PTR ExtraInformation;
		//     ULONG IssuingThreadId;
		//     ULONG InfoClass;
		// } PERFINFO_FILE_INFORMATION, *PPERFINFO_FILE_INFORMATION;
		e.SetParam(params.FileIrpPtr, params.U64(r.ReadUint64(0)))
		e.SetParam(params.FileObject, params.U64(r.ReadUint64(8)))
		e.SetParam(params.FileKey, params.U64(r.ReadUint64(16)))
		e.SetParam(params.FileExtraInfo, params.U64(r.ReadUint64(24)))
		e.SetParam(params.ThreadID, params.U32(r.ReadUint32(32)))
		e.SetParam(params.FileInfoClass, params.U32(r.ReadUint32(36)))
	case ReleaseFile, CloseFile:
		// typedef struct _PERFINFO_FILE_SIMPLE_OPERATION {
		//     ULONG_PTR Irp;
		//     ULONG_PTR FileObject;
		//     ULONG_PTR FileKey;
		//     ULONG IssuingThreadId;
		// } PERFINFO_FILE_SIMPLE_OPERATION, *PPERFINFO_FILE_SIMPLE_OPERATION;
		e.SetParam(params.FileIrpPtr, params.U64(r.ReadUint64(0)))
		e.SetParam(params.FileObject, params.U64(r.ReadUint64(8)))
		e.SetParam(params.FileKey, params.U64(r.ReadUint64(16)))
		e.SetParam(params.ThreadID, params.U32(r.ReadUint32(24)))
	case ReadFile, WriteFile:
		// typedef struct _PERFINFO_FILE_READ_WRITE {
		//     ULONGLONG Offset;
		//     ULONG_PTR Irp;
		//     ULONG_PTR FileObject;
		//     ULONG_PTR FileKey;
		//     ULONG IssuingThreadId;
		//     ULONG Size;
		//     ULONG Flags;
		//     ULONG ExtraFlags;
		// } PERFINFO_FILE_READ_WRITE, *PPERFINFO_FILE_READ_WRITE;
		e.SetParam(params.FileOffset, params.U64(r.ReadUint64(0)))
		e.SetParam(params.FileIrpPtr, params.U64(r.ReadUint64(8)))
		e.SetParam(params.FileObject, params.U64(r.ReadUint64(16)))
		e.SetParam(params.FileKey, params.U64(r.ReadUint64(24)))
		e.SetParam(params.ThreadID, params.U32(r.ReadUint32(32)))
		e.SetParam(params.FileIoSize, params.U32(r.ReadUint32(36)))
	case EnumDirectory:
		// typedef struct _PERFINFO_FILE_DIRENUM {
		//     ULONG_PTR Irp;
		//     ULONG_PTR FileObject;
		//     ULONG_PTR FileKey;
		//     ULONG IssuingThreadId;
		//     ULONG Length;
		//     ULONG InfoClass;
		//     ULONG FileIndex;
		//     WCHAR FileName[1];
		// } PERFINFO_FILE_DIRENUM, *PPERFINFO_FILE_DIRENUM;
		e.SetParam(params.FileIrpPtr, params.U64(r.ReadUint64(0)))
		e.SetParam(params.FileObject, params.U64(r.ReadUint64(8)))
		e.SetParam(params.FileKey, params.U64(r.ReadUint64(16)))
		e.SetParam(params.ThreadID, params.U32(r.ReadUint32(24)))
		// skip Length (uint32)
		e.SetParam(params.FileInfoClass, params.U32(r.ReadUint32(32)))
		// skip FileIndex (uint32)
		e.SetParam(params.FilePath, params.Str(r.ConsumeUTF16String(40)))
	case FileRundown:
		e.SetParam(params.FileObject, params.U64(r.ReadUint64(0)))
		e.SetParam(params.FilePath, params.Str(r.ConsumeUTF16String(8)))
	}
}

// DecodeProcess decodes process creation/termination/rundown event payloads.
func (d *ParamDecoder) DecodeProcess(r *etw.EventRecord, e *Event) {
	// 	typedef struct _WMI_PROCESS_INFORMATION {
	//     ULONG_PTR UniqueProcessKey;
	//     ULONG ProcessId;
	//     ULONG ParentId;
	//     ULONG SessionId;
	//     NTSTATUS ExitStatus;
	//     ULONG_PTR DirectoryTableBase;
	//     ULONG Flags;
	//     ULONG Sid;
	//     // Variable length sid
	//     // FileName (ansi string)
	//     // CommandLine (unicode string)
	//     // PackageFullName (unicode string)
	//     // PRAID (unicode string)
	// } WMI_PROCESS_INFORMATION, *PWMI_PROCESS_INFORMATION;
	const offset = 32
	sid, soffset := r.ReadSID(offset+4, true)
	name, noffset := r.ReadAnsiString(soffset)
	cmdline, _ := r.ReadUTF16String(noffset)

	e.SetParam(params.ProcessObject, params.U64(r.ReadUint64(0)))
	e.SetParam(params.ProcessID, params.U32(r.ReadUint32(8)))
	e.SetParam(params.ProcessParentID, params.U32(r.ReadUint32(12)))
	e.SetParam(params.SessionID, params.U32(r.ReadUint32(16)))
	e.SetParam(params.ExitStatus, params.U32(r.ReadUint32(20)))
	e.SetParam(params.DTB, params.U64(r.ReadUint64(24)))
	e.SetParam(params.ProcessFlags, params.U32(r.ReadUint32(32)))
	e.SetParam(params.UserSID, params.Bin(sid))
	e.SetParam(params.ProcessName, params.Str(name))
	e.SetParam(params.Cmdline, params.Str(cmdline))
	e.SetParam(params.ProcessRealParentID, params.U32(r.Header.ProcessID))
}

// DecodeProcessInternal decodes process creation/rundown event payloads
// for internal events that are used to enrich the core NT Kernel logger
// process events.
func (d *ParamDecoder) DecodeProcessInternal(r *etw.EventRecord, e *Event) {
	// <template tid="ProcessStartArgs_V4">
	//    <data name="ProcessID" inType="win:UInt32" />
	//    <data name="ProcessSequenceNumber" inType="win:UInt64" />
	//    <data name="CreateTime" inType="win:FILETIME" />
	//    <data name="ParentProcessID" inType="win:UInt32" />
	//    <data name="ParentProcessSequenceNumber" inType="win:UInt64" />
	//    <data name="SessionID" inType="win:UInt32" />
	//    <data name="Flags" inType="win:UInt32" />
	//    <data name="ProcessTokenElevationType" inType="win:UInt32" />
	//    <data name="ProcessTokenIsElevated" inType="win:UInt32" />
	//    <data name="MandatoryLabel" inType="win:SID" />
	//    <data name="ImageName" inType="win:UnicodeString" />
	//    <data name="ImageChecksum" inType="win:UInt32" />
	//    <data name="TimeDateStamp" inType="win:UInt32" />
	//    <data name="PackageFullName" inType="win:UnicodeString" />
	//    <data name="PackageRelativeAppId" inType="win:UnicodeString" />
	//    <data name="SecurityMitigations" inType="win:UInt32" />
	// </template>
	e.SetParam(params.ProcessID, params.U32(r.ReadUint32(0)))
	e.SetParam(params.ProcessObject, params.U64(r.ReadUint64(4)))

	createTime := windows.NsecToFiletime(int64(r.ReadUint64(12)))
	e.SetParam(params.StartTime, params.Timestamp(filetime.ToEpoch(uint64(createTime.Nanoseconds()))))

	e.SetParam(params.ProcessParentID, params.U32(r.ReadUint32(20)))
	// skip ParentProcessSequenceNumber (uint64)
	e.SetParam(params.SessionID, params.U32(r.ReadUint32(32)))
	e.SetParam(params.ProcessFlags, params.U32(r.ReadUint32(36)))
	e.SetParam(params.ProcessTokenElevationType, params.U32(r.ReadUint32(40)))
	e.SetParam(params.ProcessTokenIsElevated, params.Boolean(r.ReadUint32(44) > 0))

	tokenMandatoryLabel, _ := r.ReadSID(48, false) // integrity level SID size is 12 bytes
	e.SetParam(params.ProcessTokenIntegrityLevel, params.Bin(tokenMandatoryLabel))

	exe, _ := r.ReadNTUnicodeString(60)
	e.SetParam(params.Exe, params.Str(exe))
}

// DecodeModule decodes module load/unload/rundown event payloads.
func (d *ParamDecoder) DecodeModule(r *etw.EventRecord, e *Event) {
	// typedef struct _WMI_IMAGELOAD_INFORMATION64 {
	//     ULONG64 ImageBase64;
	//     ULONG64 ImageSize64;
	//     ULONG ProcessId;
	//     ULONG ImageChecksum;
	//     ULONG TimeDateStamp;
	//     UCHAR SignatureLevel;
	//     UCHAR SignatureType;
	//     USHORT Reserved0;
	//     ULONG64 DefaultBase64;
	//     ULONG Reserved1;
	//     ULONG Reserved2;
	//     ULONG Reserved3;
	//     ULONG Reserved4;
	//     WCHAR FileName[1];
	// } WMI_IMAGELOAD_INFORMATION64, *PWMI_IMAGELOAD_INFORMATION64;
	e.SetParam(params.ModuleBase, params.U64(r.ReadUint64(0)))
	e.SetParam(params.ModuleSize, params.U64(r.ReadUint64(8)))
	e.SetParam(params.ProcessID, params.U32(r.ReadUint32(16)))
	e.SetParam(params.ModuleCheckSum, params.U32(r.ReadUint32(20)))
	e.SetParam(params.ModuleTimeDateStamp, params.U32(r.ReadUint32(24)))
	e.SetParam(params.ModuleSignatureLevel, params.U32(uint32(r.ReadByte(28))))
	e.SetParam(params.ModuleSignatureType, params.U32(uint32(r.ReadByte(29))))
	// skip Reserved0 (uint8)
	e.SetParam(params.ModuleDefaultBase, params.U64(r.ReadUint64(32)))
	// skip Reserved1-Reserved4 (uint32 * 4)
	const offset = 56
	e.SetParam(params.ModulePath, params.Str(r.ConsumeUTF16String(offset)))
}

// DecodeModuleInternal decodes module load event payload for internal events
// that are used to make the process snapshotter more resistant in light of
// module lookups that might not be registered when the event from the security
// logger session is published.
func (d *ParamDecoder) DecodeModuleInternal(r *etw.EventRecord, e *Event) {
	// <template tid="ImageLoadArgs">
	//    <data name="ImageBase" inType="win:Pointer" />
	//    <data name="ImageSize" inType="win:Pointer" />
	//    <data name="ProcessID" inType="win:UInt32" />
	//    <data name="ImageCheckSum" inType="win:UInt32" />
	//    <data name="TimeDateStamp" inType="win:UInt32" />
	//    <data name="DefaultBase" inType="win:Pointer" />
	//    <data name="ImageName" inType="win:UnicodeString" />
	// </template>
	e.SetParam(params.ModuleBase, params.U64(r.ReadUint64(0)))
	e.SetParam(params.ModuleSize, params.U64(r.ReadUint64(8)))
	e.SetParam(params.ProcessID, params.U32(r.ReadUint32(16)))
	e.SetParam(params.ModuleCheckSum, params.U32(r.ReadUint32(20)))
	// skip TimeDateStamp (uint32)
	e.SetParam(params.ModuleDefaultBase, params.U64(r.ReadUint64(28)))
	e.SetParam(params.ModulePath, params.Str(r.ConsumeUTF16String(36)))
}

// DecodeThread decodes the event payload for thread creation/termination
// and thread rundown events.
func (d *ParamDecoder) DecodeThread(r *etw.EventRecord, e *Event) {
	// typedef struct _WMI_EXTENDED_THREAD_INFORMATION64 {
	//     ULONG ProcessId;
	//     ULONG ThreadId;
	//     ULONG64 StackBase64;
	//     ULONG64 StackLimit64;
	//     ULONG64 UserStackBase64;
	//     ULONG64 UserStackLimit64;
	//     union {
	//         ULONG64 StartAddr64;
	//         ULONG64 Affinity;
	//     } DUMMYUNIONNAME;
	//     ULONG64 Win32StartAddr64;
	//     ULONG64 TebBase64;
	//     ULONG SubProcessTag;
	//     SCHAR BasePriority;
	//     UCHAR PagePriority;
	//     UCHAR IoPriority;
	//     UCHAR Flags;
	// } WMI_EXTENDED_THREAD_INFORMATION64, *PWMI_EXTENDED_THREAD_INFORMATION64;
	e.SetParam(params.ProcessID, params.U32(r.ReadUint32(0)))
	e.SetParam(params.ThreadID, params.U32(r.ReadUint32(4)))
	e.SetParam(params.KstackBase, params.U64(r.ReadUint64(8)))
	e.SetParam(params.KstackLimit, params.U64(r.ReadUint64(16)))
	e.SetParam(params.UstackBase, params.U64(r.ReadUint64(24)))
	e.SetParam(params.UstackLimit, params.U64(r.ReadUint64(32)))
	// skip StartAddr64 (uint64)
	e.SetParam(params.StartAddress, params.U64(r.ReadUint64(48)))
	e.SetParam(params.TEB, params.U64(r.ReadUint64(56)))
	// skip SubProcessTag (uint32)
	e.SetParam(params.BasePrio, params.U8(r.ReadByte(68)))
	e.SetParam(params.PagePrio, params.U8(r.ReadByte(69)))
	e.SetParam(params.IOPrio, params.U8(r.ReadByte(70)))
}

// DecodeOpenThread decodes the payload for the OpenThread event.
func (d *ParamDecoder) DecodeOpenThread(r *etw.EventRecord, e *Event) {
	e.SetParam(params.ProcessID, params.U32(r.ReadUint32(0)))
	e.SetParam(params.ThreadID, params.U32(r.ReadUint32(4)))
	e.SetParam(params.DesiredAccess, params.U32(r.ReadUint32(8)))
	e.SetParam(params.NTStatus, params.U32(r.ReadUint32(12)))
	//e.SetParam(params.Callstack, Addresses(r.Callstack()))
}

// DecodeSetThreadContext decodes the payload for the SetThreadContext event.
func (d *ParamDecoder) DecodeSetThreadContext(r *etw.EventRecord, e *Event) {
	e.SetParam(params.NTStatus, params.U32(r.ReadUint32(0)))
	//e.SetParam(params.Callstack, Addresses(r.Callstack()))
}

// DecodeCreateSymbolicLinkObject decodes the payload for the CreateSymbolicLinkObject event.
func (d *ParamDecoder) DecodeCreateSymbolicLinkObject(r *etw.EventRecord, e *Event) {
	source, offset := r.ReadUTF16String(0)
	target, offset := r.ReadUTF16String(offset)
	e.SetParam(params.LinkSource, params.Str(source))
	e.SetParam(params.LinkTarget, params.Str(target))
	e.SetParam(params.DesiredAccess, params.U32(r.ReadUint32(offset)))
	e.SetParam(params.NTStatus, params.U32(r.ReadUint32(offset+4)))
	//e.SetParam(params.Callstack, Addresses(r.Callstack()))
}

// DecodeStackwalk decodes stackwalk event parameters including frame return addresses.
func (d *ParamDecoder) DecodeStackwalk(r *etw.EventRecord, e *Event) {
	// typedef struct _STACK_WALK_EVENT_DATA {
	//         ULONGLONG   TimeStamp;
	//         ULONG       ProcessId;
	//         ULONG       ThreadId;
	//         PVOID       Addresses[1]; // Address of captured Stack address
	// } STACK_WALK_EVENT_DATA, *PSTACK_WALK_EVENT_DATA;
	e.SetParam(params.CallstackTimestamp, params.U64(r.ReadUint64(0)))
	e.SetParam(params.ProcessID, params.U32(r.ReadUint32(8)))
	e.SetParam(params.ThreadID, params.U32(r.ReadUint32(12)))
	//e.SetParam(params.Callstack, Addresses(r.ReadCallstack(16)))
}

// DecodeMemory decodes memory event payloads.
func (d *ParamDecoder) DecodeMemory(r *etw.EventRecord, e *Event) {
	// typedef struct _PERFINFO_VIRTUAL_ALLOC {
	//     PVOID CapturedBase;
	//     SIZE_T CapturedRegionSize;
	//     ULONG ProcessId;
	//     ULONG Flags;
	// } PERFINFO_VIRTUAL_ALLOC, *PPERFINFO_VIRTUAL_ALLOC;
	e.SetParam(params.MemBaseAddress, params.U64(r.ReadUint64(0)))
	e.SetParam(params.MemRegionSize, params.U64(r.ReadUint64(8)))
	e.SetParam(params.ProcessID, params.U32(r.ReadUint32(16)))
	e.SetParam(params.MemAllocType, params.U32(r.ReadUint32(20)))
}

// DecodeNetwork decodes TCP/UDP network events. All network event
// share the same schema layout. For IPv6 events, the IP fields are
// 128 bits long.
func (d *ParamDecoder) DecodeNetwork(r *etw.EventRecord, e *Event) {
	// typedef struct _WMI_TCPIP {
	//     ULONG Context;
	//     ULONG  Size;
	//     ULONG DestAddr;
	//     ULONG SrcAddr;
	//     USHORT DestPort;
	//     USHORT SrcPort;
	// } WMI_TCPIP, *PWMI_TCPIP;

	// typedef struct _WMI_UDP {
	//     ULONG PID;
	//     USHORT Size;
	//     ULONG DestAddr;
	//     ULONG SrcAddr;
	//     USHORT DestPort;
	//     USHORT SrcPort;
	// }WMI_UDP, *PWMI_UDP;
	e.SetParam(params.ProcessID, params.U32(r.ReadUint32(0)))
	e.SetParam(params.NetSize, params.U32(r.ReadUint32(4)))

	switch r.Header.EventDescriptor.Opcode {
	case AcceptTCPv6ID, ConnectTCPv6ID, ReconnectTCPv6ID, RetransmitTCPv6ID,
		DisconnectTCPv6ID, SendV6ID, RecvV6ID:
		e.SetParam(params.NetDIP, params.IP6(r.ReadBytes(8, 16)))
		e.SetParam(params.NetSIP, params.IP6(r.ReadBytes(24, 16)))
		e.SetParam(params.NetDport, params.U16(windows.Ntohs(r.ReadUint16(40))))
		e.SetParam(params.NetSport, params.U16(windows.Ntohs(r.ReadUint16(42))))
	default:
		e.SetParam(params.NetDIP, params.IPv4LE(r.ReadUint32(8)))
		e.SetParam(params.NetSIP, params.IPv4LE(r.ReadUint32(12)))
		e.SetParam(params.NetDport, params.U16(windows.Ntohs(r.ReadUint16(16))))
		e.SetParam(params.NetSport, params.U16(windows.Ntohs(r.ReadUint16(18))))
	}

	if r.Header.ProviderID == NetworkTCPEventGUID {
		e.SetParam(params.NetL4Proto, params.U32(uint32(network.TCP)))
	} else {
		e.SetParam(params.NetL4Proto, params.U32(uint32(network.UDP)))
	}
}

// DecodeDNS decodes DNS query/reply event payloads.
func (d *ParamDecoder) DecodeDNS(r *etw.EventRecord, e *Event) {
	name, offset := r.ReadUTF16String(0)
	e.SetParam(params.DNSName, params.Str(name))
	e.SetParam(params.DNSRR, params.U32(r.ReadUint32(offset)))
	e.SetParam(params.DNSOpts, params.U64(r.ReadUint64(offset+4)))

	if r.Header.EventDescriptor.ID == ReplyDNSID {
		e.SetParam(params.DNSRcode, params.U32(r.ReadUint32(offset+12)))
		answers := strings.Split(sanitizeDNSAnswers(r.ConsumeUTF16String(offset+16)), ";")
		e.SetParam(params.DNSAnswers, params.StrSlice(answers))
	}
}

// sanitizeDNSAnswers removes the "type" string from DNS answers.
func sanitizeDNSAnswers(answers string) string {
	return strings.ReplaceAll(answers, "type: 5 ", "")
}
