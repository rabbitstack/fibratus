/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package params

import (
	"encoding/binary"
	"slices"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/rabbitstack/fibratus/pkg/util/utf16"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// WireFormat describes how a param is laid out in the raw event buffer.
// The zero value means the param is not in the buffer so it is appended
// in the post enrichment lifecycle.
type WireFormat uint8

const (
	WireNone WireFormat = iota // enrichment, appended after decoding
	WireSkip                   // reserved bytes, nothing is emitted
	WireU8
	WireU16
	WireU32
	WireU64
	WireU32Bool
	WireAnsi         // NUL-terminated ANSI string
	WireUTF16        // NUL-terminated UTF-16 string
	WireUTF16Trailer // NUL-terminated UTF-16 string occupies remaining event buffer
	WireNTUnicode    // UTF-16 string for NT native APIs
	WireSID          // TOKEN_USER-prefixed variable length SID
	WireWbemSID
	WireBytes
	WireBytesU16 // uint16 length prefix + bytes payload
	WireIP
	WirePort
	WireFileTime
	WireAddrs   // call stack return addresses
	WireU32Bits // one uint32 that encodes several parameters
	WireU64Bits // one uint64 that encodes several parameters
)

// ShiftDir describes the bit shift direction.
type ShiftDir uint8

const (
	ShiftNone ShiftDir = iota
	ShiftRight
	ShiftLeft
)

type Unsigned interface {
	~uint32 | ~uint64
}

type BitField struct {
	Shift uint8
	Dir   ShiftDir
	Mask  uint64
}

// extract applies the bit field to a raw value of any unsigned width.
// Right shift: shift, then mask (pull a field out of the high bits).
// Left shift:  mask, then shift (so bits aren't lost before masking).
func extract[T, V Unsigned](b *BitField, n T) V {
	mask := T(b.Mask) // truncates to the width of T
	switch b.Dir {
	case ShiftRight:
		n >>= b.Shift
		if mask != 0 {
			n &= mask
		}
	case ShiftLeft:
		if mask != 0 {
			n &= mask
		}
		n <<= b.Shift
	default:
		if mask != 0 {
			n &= mask
		}
	}
	return V(n)
}

func (b *BitField) ExtractU32(n uint32) uint32 {
	return extract[uint32, uint32](b, n)
}

func (b *BitField) ExtractU64(n uint64) uint32 {
	return extract[uint64, uint32](b, n)
}

type ParamInfo struct {
	BaseParamInfo

	WireFormat WireFormat // how to read it from the buffer
	Size       uint16     // how many bytes to read or skip (WireSkip and WireBytes only)

	// Interpret turns a raw blob into a typed param value usually
	// based on a param decoded earlier in the same event.
	Interpret func(selector uint32, raw []byte) Value
	// Selector is an earlier param whose value picks the interpretation.
	Selector string

	// Into is the param that receives the interpreted value.
	// Empty means the result is stored under Name.
	Into string

	// FromRecord builds the parameter value by directly accessing
	// the raw event record.
	FromRecord func(rec *etw.EventRecord) Value

	// Sanitize apply sanitization/transformation on the input string.
	Sanitize func(s string) Value

	// Derives are extra params sliced out of the same encoded value. Their
	// parameter info descriptors must be declared next to the value from
	// whose they're derived. BitField describes the bit layout for packed
	// parameter types.
	Derives []*BitField
}

// Parameter schemas. The parameters are declared in the order in which they are decoded from the
// event buffer. The parameters that are appended by the event processors, the process snapshotter,
// the symbolizer, or the callstack linker are listed after the decoded ones.

// CreateProcessDescriptor
//
//	typedef struct _WMI_PROCESS_INFORMATION {
//	    ULONG_PTR UniqueProcessKey;
//	    ULONG ProcessId;
//	    ULONG ParentId;
//	    ULONG SessionId;
//	    NTSTATUS ExitStatus;
//	    ULONG_PTR DirectoryTableBase;
//	    ULONG Flags;
//	    ULONG Sid;
//	    // Variable length sid
//	    // FileName (ansi string)
//	    // CommandLine (unicode string)
//	    // PackageFullName (unicode string)
//	    // PRAID (unicode string)
//	} WMI_PROCESS_INFORMATION, *PWMI_PROCESS_INFORMATION;
var CreateProcessDescriptor = []ParamInfo{
	{Name: ProcessObject, Type: Address, WireFormat: WireU64},
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ProcessParentID, Type: PID, WireFormat: WireU32},
	{Name: SessionID, Type: Uint32, WireFormat: WireU32},
	{Name: ExitStatus, Type: Status, WireFormat: WireU32},
	{Name: DTB, Type: Address, WireFormat: WireU64},
	{Name: ProcessFlags, Type: Flags32, WireFormat: WireU32, Flags: PsCreationFlags},
	{Name: UserSID, Type: WbemSID, WireFormat: WireWbemSID},
	{Name: ProcessName, Type: String, WireFormat: WireAnsi},
	{Name: Cmdline, Type: String, WireFormat: WireUTF16},
	{Name: ProcessRealParentID, Type: PID, FromRecord: func(rec *etw.EventRecord) Value {
		return U32(rec.Header.ProcessID)
	}},
	{Name: Exe, Type: Path},
	{Name: StartTime, Type: Time},
	{Name: ProcessTokenIntegrityLevel, Type: TokenIntegrityLevel},
	{Name: ProcessTokenElevationType, Type: Enum, Enum: PsTokenElevationTypes},
	{Name: ProcessTokenIsElevated, Type: Bool},
	{Name: Username, Type: String},
	{Name: Domain, Type: String},
	{Name: Callstack, Type: Slice},
}

var TerminateProcessDescriptor = []ParamInfo{
	{Name: ProcessObject, Type: Address, WireFormat: WireU64},
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ProcessParentID, Type: PID, WireFormat: WireU32},
	{Name: SessionID, Type: Uint32, WireFormat: WireU32},
	{Name: ExitStatus, Type: Status, WireFormat: WireU32},
	{Name: DTB, Type: Address, WireFormat: WireU64},
	{Name: ProcessFlags, Type: Flags32, WireFormat: WireU32, Flags: PsCreationFlags},
	{Name: UserSID, Type: WbemSID, WireFormat: WireWbemSID},
	{Name: ProcessName, Type: String, WireFormat: WireAnsi},
	{Name: Cmdline, Type: String, WireFormat: WireUTF16},
}

var ProcessRundownDescriptor = []ParamInfo{
	{Name: ProcessObject, Type: Address, WireFormat: WireU64},
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ProcessParentID, Type: PID, WireFormat: WireU32},
	{Name: SessionID, Type: Uint32, WireFormat: WireU32},
	{Name: ExitStatus, Type: Status, WireFormat: WireU32},
	{Name: DTB, Type: Address, WireFormat: WireU64},
	{Name: ProcessFlags, Type: Flags32, WireFormat: WireU32, Flags: PsCreationFlags},
	{Name: UserSID, Type: WbemSID, WireFormat: WireWbemSID},
	{Name: ProcessName, Type: String, WireFormat: WireAnsi},
	{Name: Cmdline, Type: String, WireFormat: WireUTF16},
}

var OpenProcessDescriptor = []ParamInfo{
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: DesiredAccess, Type: Flags32, WireFormat: WireU32, Flags: PsAccessRightFlags},
	{Name: NTStatus, Type: Status, WireFormat: WireU32},
	{Name: Callstack, Type: Slice, FromRecord: func(rec *etw.EventRecord) Value {
		return Addresses(rec.Callstack())
	}},
	{Name: Exe, Type: Path},
	{Name: ProcessName, Type: String},
}

// <template tid="ProcessStartArgs_V4">
//
//	<data name="ProcessID" inType="win:UInt32" />
//	<data name="ProcessSequenceNumber" inType="win:UInt64" />
//	<data name="CreateTime" inType="win:FILETIME" />
//	<data name="ParentProcessID" inType="win:UInt32" />
//	<data name="ParentProcessSequenceNumber" inType="win:UInt64" />
//	<data name="SessionID" inType="win:UInt32" />
//	<data name="Flags" inType="win:UInt32" />
//	<data name="ProcessTokenElevationType" inType="win:UInt32" />
//	<data name="ProcessTokenIsElevated" inType="win:UInt32" />
//	<data name="MandatoryLabel" inType="win:SID" />
//	<data name="ImageName" inType="win:UnicodeString" />
//	<data name="ImageChecksum" inType="win:UInt32" />
//	<data name="TimeDateStamp" inType="win:UInt32" />
//	<data name="PackageFullName" inType="win:UnicodeString" />
//	<data name="PackageRelativeAppId" inType="win:UnicodeString" />
//	<data name="SecurityMitigations" inType="win:UInt32" />
//
// </template>
var CreateProcessInternalDescriptor = []ParamInfo{
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ProcessSequenceNumber, Type: Uint64, WireFormat: WireU64},
	{Name: StartTime, Type: Time, WireFormat: WireFileTime},
	{Name: ProcessParentID, Type: PID, WireFormat: WireU32},
	{Name: ParentProcessSequenceNumber, Type: Uint64, WireFormat: WireU64},
	{Name: SessionID, Type: Uint32, WireFormat: WireU32},
	{Name: ProcessFlags, Type: Flags32, WireFormat: WireU32, Flags: PsCreationFlags},
	{Name: ProcessTokenElevationType, Type: Enum, WireFormat: WireU32, Enum: PsTokenElevationTypes},
	{Name: ProcessTokenIsElevated, Type: Bool, WireFormat: WireU32Bool},
	{Name: ProcessTokenIntegrityLevel, Type: TokenIntegrityLevel, WireFormat: WireSID},
	{Name: Exe, Type: DOSPath, WireFormat: WireNTUnicode},
}

var ProcessRundownInternalDescriptor = CreateProcessInternalDescriptor

//	typedef struct _WMI_EXTENDED_THREAD_INFORMATION64 {
//	    ULONG ProcessId;
//	    ULONG ThreadId;
//	    ULONG64 StackBase64;
//	    ULONG64 StackLimit64;
//	    ULONG64 UserStackBase64;
//	    ULONG64 UserStackLimit64;
//	    union {
//	        ULONG64 StartAddr64;
//	        ULONG64 Affinity;
//	    } DUMMYUNIONNAME;
//	    ULONG64 Win32StartAddr64;
//	    ULONG64 TebBase64;
//	    ULONG SubProcessTag;
//	    SCHAR BasePriority;
//	    UCHAR PagePriority;
//	    UCHAR IoPriority;
//	    UCHAR Flags;
//	} WMI_EXTENDED_THREAD_INFORMATION64, *PWMI_EXTENDED_THREAD_INFORMATION64;
var CreateThreadDescriptor = []ParamInfo{
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{Name: KstackBase, Type: Address, WireFormat: WireU64},
	{Name: KstackLimit, Type: Address, WireFormat: WireU64},
	{Name: UstackBase, Type: Address, WireFormat: WireU64},
	{Name: UstackLimit, Type: Address, WireFormat: WireU64},
	{WireFormat: WireSkip, Size: 8},
	{Name: StartAddress, Type: Address, WireFormat: WireU64},
	{Name: TEB, Type: Address, WireFormat: WireU64},
	{WireFormat: WireSkip, Size: 4},
	{Name: BasePrio, Type: Uint8, WireFormat: WireU8},
	{Name: PagePrio, Type: Uint8, WireFormat: WireU8},
	{Name: IOPrio, Type: Uint8, WireFormat: WireU8},
	{Name: Exe, Type: Path},
	{Name: Callstack, Type: Slice},
	{Name: StartAddressSymbol, Type: String},
	{Name: StartAddressModule, Type: Path},
}

var TerminateThreadDescriptor = []ParamInfo{
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{Name: KstackBase, Type: Address, WireFormat: WireU64},
	{Name: KstackLimit, Type: Address, WireFormat: WireU64},
	{Name: UstackBase, Type: Address, WireFormat: WireU64},
	{Name: UstackLimit, Type: Address, WireFormat: WireU64},
	{WireFormat: WireSkip, Size: 8},
	{Name: StartAddress, Type: Address, WireFormat: WireU64},
	{Name: TEB, Type: Address, WireFormat: WireU64},
	{WireFormat: WireSkip, Size: 4},
	{Name: BasePrio, Type: Uint8, WireFormat: WireU8},
	{Name: PagePrio, Type: Uint8, WireFormat: WireU8},
	{Name: IOPrio, Type: Uint8, WireFormat: WireU8},
	{Name: Exe, Type: Path},
	{Name: Callstack, Type: Slice},
}

var ThreadRundownDescriptor = []ParamInfo{
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{Name: KstackBase, Type: Address, WireFormat: WireU64},
	{Name: KstackLimit, Type: Address, WireFormat: WireU64},
	{Name: UstackBase, Type: Address, WireFormat: WireU64},
	{Name: UstackLimit, Type: Address, WireFormat: WireU64},
	{WireFormat: WireSkip, Size: 8},
	{Name: StartAddress, Type: Address, WireFormat: WireU64},
	{Name: TEB, Type: Address, WireFormat: WireU64},
	{WireFormat: WireSkip, Size: 4},
	{Name: BasePrio, Type: Uint8, WireFormat: WireU8},
	{Name: PagePrio, Type: Uint8, WireFormat: WireU8},
	{Name: IOPrio, Type: Uint8, WireFormat: WireU8},
}

var OpenThreadDescriptor = []ParamInfo{
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{Name: DesiredAccess, Type: Flags32, WireFormat: WireU32, Flags: ThreadAccessRightFlags},
	{Name: NTStatus, Type: Status, WireFormat: WireU32},
	{Name: Callstack, Type: Slice, FromRecord: func(rec *etw.EventRecord) Value {
		return Addresses(rec.Callstack())
	}},
	{Name: Exe, Type: Path},
	{Name: ProcessName, Type: String},
}

var SetThreadContextDescriptor = []ParamInfo{
	{Name: NTStatus, Type: Status, WireFormat: WireU32},
	{Name: Callstack, Type: Slice, FromRecord: func(rec *etw.EventRecord) Value {
		return Addresses(rec.Callstack())
	}},
}

//	typedef struct _STACK_WALK_EVENT_DATA {
//	        ULONGLONG   TimeStamp;
//	        ULONG       ProcessId;
//	        ULONG       ThreadId;
//	        PVOID       Addresses[1]; // Address of captured Stack address
//	} STACK_WALK_EVENT_DATA, *PSTACK_WALK_EVENT_DATA;
var StackWalkDescriptor = []ParamInfo{
	{Name: CallstackTimestamp, Type: Uint64, WireFormat: WireU64},
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{Name: Callstack, Type: Slice, WireFormat: WireAddrs},
}

//	typedef struct _WMI_IMAGELOAD_INFORMATION64 {
//	    ULONG64 ImageBase64;
//	    ULONG64 ImageSize64;
//	    ULONG ProcessId;
//	    ULONG ImageChecksum;
//	    ULONG TimeDateStamp;
//	    UCHAR SignatureLevel;
//	    UCHAR SignatureType;
//	    USHORT Reserved0;
//	    ULONG64 DefaultBase64;
//	    ULONG Reserved1;
//	    ULONG Reserved2;
//	    ULONG Reserved3;
//	    ULONG Reserved4;
//	    WCHAR FileName[1];
//	} WMI_IMAGELOAD_INFORMATION64, *PWMI_IMAGELOAD_INFORMATION64;
var LoadModuleDescriptor = []ParamInfo{
	{Name: ModuleBase, Type: Address, WireFormat: WireU64},
	{Name: ModuleSize, Type: Uint64, WireFormat: WireU64},
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ModuleCheckSum, Type: Uint32, WireFormat: WireU32},
	{Name: ModuleTimeDateStamp, Type: Uint32, WireFormat: WireU32},
	{Name: ModuleSignatureLevel, Type: Enum, WireFormat: WireU8, Enum: signature.Levels},
	{Name: ModuleSignatureType, Type: Enum, WireFormat: WireU8, Enum: signature.Types},
	{WireFormat: WireSkip, Size: 2},
	{Name: ModuleDefaultBase, Type: Address, WireFormat: WireU64},
	{WireFormat: WireSkip, Size: 4},
	{WireFormat: WireSkip, Size: 4},
	{WireFormat: WireSkip, Size: 4},
	{WireFormat: WireSkip, Size: 4},
	{Name: ModulePath, Type: DOSPath, WireFormat: WireUTF16Trailer},
	{Name: Callstack, Type: Slice},
	{Name: ModuleCertIssuer, Type: String},
	{Name: ModuleCertSubject, Type: String},
	{Name: ModuleCertSerial, Type: String},
	{Name: ModuleCertNotAfter, Type: Time},
	{Name: ModuleCertNotBefore, Type: Time},
}

var UnloadModuleDescriptor = []ParamInfo{
	{Name: ModuleBase, Type: Address, WireFormat: WireU64},
	{Name: ModuleSize, Type: Uint64, WireFormat: WireU64},
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ModuleCheckSum, Type: Uint32, WireFormat: WireU32},
	{Name: ModuleTimeDateStamp, Type: Uint32, WireFormat: WireU32},
	{Name: ModuleSignatureLevel, Type: Enum, WireFormat: WireU8, Enum: signature.Levels},
	{Name: ModuleSignatureType, Type: Enum, WireFormat: WireU8, Enum: signature.Types},
	{WireFormat: WireSkip, Size: 2},
	{Name: ModuleDefaultBase, Type: Address, WireFormat: WireU64},
	{WireFormat: WireSkip, Size: 4},
	{WireFormat: WireSkip, Size: 4},
	{WireFormat: WireSkip, Size: 4},
	{WireFormat: WireSkip, Size: 4},
	{Name: ModulePath, Type: DOSPath, WireFormat: WireUTF16Trailer},
}

var ModuleRundownDescriptor = UnloadModuleDescriptor

// <template tid="ImageLoadArgs">
//
//	<data name="ImageBase" inType="win:Pointer" />
//	<data name="ImageSize" inType="win:Pointer" />
//	<data name="ProcessID" inType="win:UInt32" />
//	<data name="ImageCheckSum" inType="win:UInt32" />
//	<data name="TimeDateStamp" inType="win:UInt32" />
//	<data name="DefaultBase" inType="win:Pointer" />
//	<data name="ImageName" inType="win:UnicodeString" />
//
// </template>
var LoadModuleInternalDescriptor = []ParamInfo{
	{Name: ModuleBase, Type: Address, WireFormat: WireU64},
	{Name: ModuleSize, Type: Uint64, WireFormat: WireU64},
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: ModuleCheckSum, Type: Uint32, WireFormat: WireU32},
	{Name: ModuleTimeDateStamp, Type: Uint32, WireFormat: WireU32},
	{Name: ModuleDefaultBase, Type: Address, WireFormat: WireU64},
	{Name: ModulePath, Type: DOSPath, WireFormat: WireUTF16Trailer},
}

// RegistryDescriptor represents the parameters schema for registry events.
// Many registry events share the same binary layout as defined by the C struct
//
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
var RegistryDescriptor = []ParamInfo{
	{WireFormat: WireSkip, Size: 8},
	{Name: NTStatus, Type: Status, WireFormat: WireU32},
	{WireFormat: WireSkip, Size: 4},
	{Name: RegKCB, Type: Address, WireFormat: WireU64},
	{Name: RegPath, Type: Key, WireFormat: WireUTF16Trailer},
}

var RegCreateKeyDescriptor = slices.Concat(RegistryDescriptor, []ParamInfo{{Name: Callstack, Type: Slice}})
var RegDeleteKeyDescriptor = slices.Concat(RegistryDescriptor, []ParamInfo{{Name: Callstack, Type: Slice}})
var RegDeleteValueDescriptor = slices.Concat(RegistryDescriptor, []ParamInfo{{Name: Callstack, Type: Slice}})

var RegSetValueDescriptor = []ParamInfo{
	{WireFormat: WireSkip, Size: 8},
	{Name: NTStatus, Type: Status, WireFormat: WireU32},
	{WireFormat: WireSkip, Size: 4},
	{Name: RegKCB, Type: Address, WireFormat: WireU64},
	{Name: RegValue, Type: String, WireFormat: WireUTF16Trailer},
	{Name: RegPath, Type: Key},
	{Name: RegValueType, Type: Enum, Enum: key.RegistryValueTypes},
	{Name: RegData, Type: Variant},
	{Name: Callstack, Type: Slice},
}

// The event describes a registry value modification operation and contains
// both metadata about the target registry value and a captured snapshot of
// the written data buffer.
//
// <template tid="task_0SetValueKeyArgs">
//
//	<data name="KeyObject" inType="win:Pointer" />
//	<data name="Status" inType="win:UInt32" />
//	<data name="Type" inType="win:UInt32" />
//	<data name="DataSize" inType="win:UInt32" />
//	<data name="KeyName" inType="win:UnicodeString" />
//	<data name="ValueName" inType="win:UnicodeString" />
//	<data name="CapturedDataSize" inType="win:UInt16" />
//	<data name="CapturedData" inType="win:Binary" length="CapturedDataSize" />
//	<data name="PreviousDataType" inType="win:UInt32" />
//	<data name="PreviousDataSize" inType="win:UInt32" />
//	<data name="PreviousDataCapturedSize" inType="win:UInt16" />
//	<data name="PreviousData" inType="win:Binary" length="PreviousDataCapturedSize" />
//
// </template>
var RegSetValueInternalDescriptor = []ParamInfo{
	{Name: RegKeyHandle, Type: Address, WireFormat: WireU64},
	{Name: NTStatus, Type: Status, WireFormat: WireU32},
	{Name: RegValueType, Type: Enum, WireFormat: WireU32, Enum: key.RegistryValueTypes},
	{WireFormat: WireSkip, Size: 4},
	{Name: RegPath, Type: String, WireFormat: WireUTF16},
	{Name: RegValue, Type: String, WireFormat: WireUTF16},
	{Name: RegData, Type: Variant, WireFormat: WireBytesU16, Interpret: func(selector uint32, b []byte) Value {
		switch selector {
		case registry.SZ, registry.EXPAND_SZ, registry.LINK:
			return Str(utf16.BytesToString(b, binary.LittleEndian))
		case registry.MULTI_SZ:
			return StrSlice(key.MultiSZ(b))
		case registry.DWORD:
			return U32(uint32(key.Uint(b, binary.LittleEndian)))
		case registry.DWORD_BIG_ENDIAN:
			return U32(uint32(key.Uint(b, binary.BigEndian)))
		case registry.QWORD:
			return U64(key.Uint(b, binary.LittleEndian))
		default:
			// BINARY, NONE, RESOURCE_*, and any undefined type
			return Bin(b)
		}
	}, Selector: RegValueType, Into: RegData},
}

// CreateFileDescriptor is the parameters schema for CreateFile events.
//
//	typedef struct _PERFINFO_FILE_CREATE {
//		    LONG_PTR Irp;
//		    ULONG_PTR FileObject;
//		    ULONG IssuingThreadId;
//		    ULONG Options;
//		    ULONG Attributes;
//		    ULONG ShareAccess;
//		    WCHAR OpenPath[1];
//		} PERFINFO_FILE_CREATE, *PPERFINFO_FILE_CREATE;
var CreateFileDescriptor = []ParamInfo{
	{Name: FileIrpPtr, Type: Address, WireFormat: WireU64},
	{Name: FileObject, Type: Address, WireFormat: WireU64},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{Name: FileOptions, Type: Uint32, WireFormat: WireU32Bits, Derives: []*BitField{
		{Mask: 0xFF, Shift: 24, Dir: ShiftRight}, // disposition
		{Mask: 0xFFFFFF},                         // create options
	}},
	{Name: FileOperation, Type: Enum, Enum: fs.FileCreateDispositions},
	{Name: FileCreateOptions, Type: Flags32, Flags: FileCreateOptionsFlags},
	{Name: FileAttributes, Type: Flags32, WireFormat: WireU32, Flags: FileAttributeFlags},
	{Name: FileShareMask, Type: Flags32, WireFormat: WireU32, Flags: FileShareModeFlags},
	{Name: FilePath, Type: DOSPath, WireFormat: WireUTF16Trailer},
	{Name: NTStatus, Type: Status},
	{Name: FileType, Type: Enum, Enum: fs.FileTypes},
	{Name: Callstack, Type: Slice},
}

//	typedef struct _PERFINFO_FILE_SIMPLE_OPERATION {
//	    ULONG_PTR Irp;
//	    ULONG_PTR FileObject;
//	    ULONG_PTR FileKey;
//	    ULONG IssuingThreadId;
//	} PERFINFO_FILE_SIMPLE_OPERATION, *PPERFINFO_FILE_SIMPLE_OPERATION;
var ReleaseFileDescriptor = []ParamInfo{
	{Name: FileIrpPtr, Type: Address, WireFormat: WireU64},
	{Name: FileObject, Type: Address, WireFormat: WireU64},
	{Name: FileKey, Type: Address, WireFormat: WireU64},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
}
var CloseFileDescriptor = []ParamInfo{
	{Name: FileIrpPtr, Type: Address, WireFormat: WireU64},
	{Name: FileObject, Type: Address, WireFormat: WireU64},
	{Name: FileKey, Type: Address, WireFormat: WireU64},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
}

// // typedef struct _PERFINFO_FILE_READ_WRITE {
// //     ULONGLONG Offset;
// //     ULONG_PTR Irp;
// //     ULONG_PTR FileObject;
// //     ULONG_PTR FileKey;
// //     ULONG IssuingThreadId;
// //     ULONG Size;
// //     ULONG Flags;
// //     ULONG ExtraFlags;
// // } PERFINFO_FILE_READ_WRITE, *PPERFINFO_FILE_READ_WRITE;
var ReadWriteFileDescriptor = []ParamInfo{
	{Name: FileOffset, Type: Uint64, WireFormat: WireU64},
	{Name: FileIrpPtr, Type: Address, WireFormat: WireU64},
	{Name: FileObject, Type: Address, WireFormat: WireU64},
	{Name: FileKey, Type: Address, WireFormat: WireU64},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{Name: FileIoSize, Type: Uint32, WireFormat: WireU32},
	{Name: FilePath, Type: Path},
	{Name: FileType, Type: Enum, Enum: fs.FileTypes},
}

//	typedef struct _PERFINFO_FILE_INFORMATION {
//	    ULONG_PTR Irp;
//	    ULONG_PTR FileObject;
//	    ULONG_PTR FileKey;
//	    ULONG_PTR ExtraInformation;
//	    ULONG IssuingThreadId;
//	    ULONG InfoClass;
//	} PERFINFO_FILE_INFORMATION, *PPERFINFO_FILE_INFORMATION;
var SetFileInformationDescriptor = []ParamInfo{
	{Name: FileIrpPtr, Type: Address, WireFormat: WireU64},
	{Name: FileObject, Type: Address, WireFormat: WireU64},
	{Name: FileKey, Type: Address, WireFormat: WireU64},
	{Name: FileExtraInfo, Type: Address, WireFormat: WireU64},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{Name: FileInfoClass, Type: Enum, WireFormat: WireU32, Enum: fs.FileInfoClasses},
	{Name: FilePath, Type: Path},
	{Name: FileType, Type: Enum, Enum: fs.FileTypes},
}

var DeleteFileDescriptor = []ParamInfo{
	{Name: FileIrpPtr, Type: Address, WireFormat: WireU64},
	{Name: FileObject, Type: Address, WireFormat: WireU64},
	{Name: FileKey, Type: Address, WireFormat: WireU64},
	{Name: FileExtraInfo, Type: Address, WireFormat: WireU64},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{Name: FileInfoClass, Type: Enum, WireFormat: WireU32, Enum: fs.FileInfoClasses},
	{Name: FilePath, Type: Path},
	{Name: FileType, Type: Enum, Enum: fs.FileTypes},
	{Name: Callstack, Type: Slice},
}

var RenameFileDescriptor = []ParamInfo{
	{Name: FileIrpPtr, Type: Address, WireFormat: WireU64},
	{Name: FileObject, Type: Address, WireFormat: WireU64},
	{Name: FileKey, Type: Address, WireFormat: WireU64},
	{Name: FileExtraInfo, Type: Address, WireFormat: WireU64},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{Name: FileInfoClass, Type: Enum, WireFormat: WireU32, Enum: fs.FileInfoClasses},
	{Name: FilePath, Type: Path},
	{Name: FileType, Type: Enum, Enum: fs.FileTypes},
	{Name: Callstack, Type: Slice},
}

//	typedef struct _PERFINFO_FILE_DIRENUM {
//	     ULONG_PTR Irp;
//	     ULONG_PTR FileObject;
//	     ULONG_PTR FileKey;
//	     ULONG IssuingThreadId;
//	     ULONG Length;
//	     ULONG InfoClass;
//	     ULONG FileIndex;
//	     WCHAR FileName[1];
//	 } PERFINFO_FILE_DIRENUM, *PPERFINFO_FILE_DIRENUM;
var EnumDirectoryDescriptor = []ParamInfo{
	{Name: FileIrpPtr, Type: Address, WireFormat: WireU64},
	{Name: FileObject, Type: Address, WireFormat: WireU64},
	{Name: FileKey, Type: Address, WireFormat: WireU64},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{WireFormat: WireSkip, Size: 4},
	{Name: FileInfoClass, Type: Enum, WireFormat: WireU32, Enum: fs.FileInfoClasses},
	{WireFormat: WireSkip, Size: 4},
	{Name: FileName, Type: String, WireFormat: WireUTF16Trailer},
	{Name: FilePath, Type: Path},
}

var FileRundownDescriptor = []ParamInfo{
	{Name: FileObject, Type: Address, WireFormat: WireU64},
	{Name: FilePath, Type: DOSPath, WireFormat: WireUTF16Trailer},
}

//	typedef struct _PERFINFO_FILE_OPERATION_END {
//	    ULONG_PTR Irp;
//	    ULONG_PTR ExtraInformation;
//	    NTSTATUS Status;
//	} PERFINFO_FILE_OPERATION_END, *PPERFINFO_FILE_OPERATION_END;
var FileOpEndDescriptor = []ParamInfo{
	{Name: FileIrpPtr, Type: Address, WireFormat: WireU64},
	{Name: FileExtraInfo, Type: Address, WireFormat: WireU64},
	{Name: NTStatus, Type: Status, WireFormat: WireU32},
}

var NetworkTCPEventGUID = windows.GUID{Data1: 0x9a280ac0, Data2: 0xc8e0, Data3: 0x11d1, Data4: [8]byte{0x84, 0xe2, 0x0, 0xc0, 0x4f, 0xb9, 0x98, 0xa2}}

// NetworkDescriptor is the schema for TCP/UDP network events. All
// network event share the same schema layout. For IPv6 events, the
// IP fields are 128 bits long.
//
// typedef struct _WMI_TCPIP {
//     ULONG Context;
//     ULONG  Size;
//     ULONG DestAddr;
//     ULONG SrcAddr;
//     USHORT DestPort;
//     USHORT SrcPort;
// } WMI_TCPIP, *PWMI_TCPIP;

//	typedef struct _WMI_UDP {
//	    ULONG PID;
//	    USHORT Size;
//	    ULONG DestAddr;
//	    ULONG SrcAddr;
//	    USHORT DestPort;
//	    USHORT SrcPort;
//	}WMI_UDP, *PWMI_UDP;
var NetworkDescriptor = []ParamInfo{
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: NetSize, Type: Uint32, WireFormat: WireU32},
	{Name: NetDIP, Type: IP, WireFormat: WireIP},
	{Name: NetSIP, Type: IP, WireFormat: WireIP},
	{Name: NetDport, Type: Port, WireFormat: WirePort},
	{Name: NetSport, Type: Port, WireFormat: WirePort},
	{Name: NetL4Proto, Type: Enum, Enum: network.ProtoNames, FromRecord: func(rec *etw.EventRecord) Value {
		if rec.Header.ProviderID == NetworkTCPEventGUID {
			return U32(uint32(network.TCP))
		}
		return U32(uint32(network.UDP))
	}},
	{Name: NetDportName, Type: String},
	{Name: NetSportName, Type: String},
}

var QueryDNSDescriptor = []ParamInfo{
	{Name: DNSName, Type: String, WireFormat: WireUTF16},
	{Name: DNSRR, Type: Enum, WireFormat: WireU32, Enum: DNSRecordTypes},
	{Name: DNSOpts, Type: Flags64, WireFormat: WireU64, Flags: DNSOptsFlags},
}

var ReplyDNSDescriptor = []ParamInfo{
	{Name: DNSName, Type: String, WireFormat: WireUTF16},
	{Name: DNSRR, Type: Enum, WireFormat: WireU32, Enum: DNSRecordTypes},
	{Name: DNSOpts, Type: Flags64, WireFormat: WireU64, Flags: DNSOptsFlags},
	{Name: DNSRcode, Type: Enum, WireFormat: WireU32, Enum: DNSResponseCodes},
	{Name: DNSAnswers, Type: Slice, WireFormat: WireUTF16, Sanitize: func(s string) Value {
		return StrSlice(strings.Split(strings.ReplaceAll(s, "type: 5 ", ""), ";"))
	}},
}

var MapViewOfSectionDescriptor = []ParamInfo{
	{Name: FileViewBase, Type: Address, WireFormat: WireU64},
	{Name: FileKey, Type: Address, WireFormat: WireU64},
	{Name: FileExtraInfo, Type: Uint64, WireFormat: WireU64Bits, Derives: []*BitField{
		{Shift: 32, Dir: ShiftRight}, // view section protection
		{Shift: 52, Dir: ShiftRight}, // view section type
	}},
	{Name: MemProtect, Type: Flags32, Flags: ViewProtectionFlags},
	{Name: FileViewSectionType, Type: Enum, Enum: ViewSectionTypes},
	{Name: FileViewSize, Type: Uint64, WireFormat: WireU64},
	{Name: FileOffset, Type: Uint64, WireFormat: WireU64},
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: FilePath, Type: Path},
	{Name: FileType, Type: Enum, Enum: fs.FileTypes},
	{Name: Exe, Type: Path},
	{Name: ProcessName, Type: String},
}

var UnmapViewOfSectionDescriptor = MapViewOfSectionDescriptor
var MapViewSectionRundownDescriptor = MapViewOfSectionDescriptor

//	typedef struct _PERFINFO_VIRTUAL_ALLOC {
//	    PVOID CapturedBase;
//	    SIZE_T CapturedRegionSize;
//	    ULONG ProcessId;
//	    ULONG Flags;
//	} PERFINFO_VIRTUAL_ALLOC, *PPERFINFO_VIRTUAL_ALLOC;
var VirtualAllocDescriptor = []ParamInfo{
	{Name: MemBaseAddress, Type: Address, WireFormat: WireU64},
	{Name: MemRegionSize, Type: Uint64, WireFormat: WireU64},
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
	{Name: MemAllocType, Type: Flags32, WireFormat: WireU32, Flags: MemAllocationFlags},
	{Name: MemPageType, Type: Enum, Enum: MemPageTypes},
	{Name: MemProtect, Type: Flags32, Flags: MemProtectionFlags},
	{Name: MemProtectMask, Type: String},
	{Name: Exe, Type: Path},
	{Name: ProcessName, Type: String},
	{Name: Callstack, Type: Slice},
}

var VirtualFreeDescriptor = []ParamInfo{
	{Name: MemBaseAddress, Type: Address, WireFormat: WireU64},
	{Name: MemRegionSize, Type: Uint64, WireFormat: WireU64},
	{Name: ProcessID, Type: PID, WireFormat: WireU32},
}

var CreateSymbolicLinkObjectDescriptor = []ParamInfo{
	{Name: LinkSource, Type: String, WireFormat: WireUTF16},
	{Name: LinkTarget, Type: String, WireFormat: WireUTF16},
	{Name: DesiredAccess, Type: Flags32, WireFormat: WireU32, Flags: AccessMaskFlags},
	{Name: NTStatus, Type: Status, WireFormat: WireU32},
	{Name: Callstack, Type: Slice, FromRecord: func(rec *etw.EventRecord) Value {
		return Addresses(rec.Callstack())
	}},
}
