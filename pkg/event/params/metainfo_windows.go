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
	"slices"

	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
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
	WireAnsi      // NUL-terminated ANSI string
	WireUTF16     // NUL-terminated UTF-16 string
	WireNTUnicode // UTF-16 string for NT native APIs
	WireSID       // TOKEN_USER-prefixed variable length SID
	WireWbemSID
	WireBytes
	WireBytesU16 // uint16 length prefix + bytes payload
	WireIP
	WirePort
	WireFileTime
	WireAddrs // call stack return addresses
)

// ShiftDir describes the bit shift direction.
type ShiftDir uint8

const (
	ShiftNone ShiftDir = iota
	ShiftRight
	ShiftLeft
)

type BitField struct {
	Shift uint8
	Dir   ShiftDir
	Mask  uint32
}

// Extract applies the field to a raw value.
// Right shift: shift, then mask (pull a field out of the high bits).
// Left shift:  mask, then shift (so bits aren't lost before masking).
func (b *BitField) Extract(n uint32) uint32 {
	switch b.Dir {
	case ShiftRight:
		n >>= b.Shift
		if b.Mask != 0 {
			n &= b.Mask
		}
	case ShiftLeft:
		if b.Mask != 0 {
			n &= b.Mask
		}
		n <<= b.Shift
	default:
		if b.Mask != 0 {
			n &= b.Mask
		}
	}
	return n
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

	// BitField describes the bit layout for packed parameter types. The
	// shift and mask extract the value by applying bitwise operations.
	BitField *BitField
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

// 	moduleParams = []ParamInfo{
// 		pi(params.ModuleBase, params.Address),
// 		pi(params.ModuleSize, params.Uint64),
// 		pi(params.ProcessID, params.PID),
// 		pi(params.ModuleCheckSum, params.Uint32),
// 		pi(params.ModuleTimeDateStamp, params.Uint32),
// 		pen(params.ModuleSignatureLevel, signature.Levels),
// 		pen(params.ModuleSignatureType, signature.Types),
// 		pi(params.ModuleDefaultBase, params.Address),
// 		pi(params.ModulePath, params.DOSPath),
// 		// enrichments
// 		pi(params.ModuleCertIssuer, params.String),
// 		pi(params.ModuleCertSubject, params.String),
// 		pi(params.ModuleCertSerial, params.String),
// 		pi(params.ModuleCertNotAfter, params.Time),
// 		pi(params.ModuleCertNotBefore, params.Time),
// 	}
// 	loadModuleParams         = slices.Concat(moduleParams, []ParamInfo{callstackParam})
// 	loadModuleInternalParams = []ParamInfo{
// 		pi(params.ModuleBase, params.Address),
// 		pi(params.ModuleSize, params.Uint64),
// 		pi(params.ProcessID, params.PID),
// 		pi(params.ModuleCheckSum, params.Uint32),
// 		pi(params.ModuleDefaultBase, params.Address),
// 		pi(params.ModulePath, params.DOSPath),
// 	}

// CreateFileDescriptor is the parameters schema for CreateFile events.
var CreateFileDescriptor = []ParamInfo{
	{Name: FileIrpPtr, Type: Address, WireFormat: WireU64},
	{Name: FileObject, Type: Address, WireFormat: WireU64},
	{Name: ThreadID, Type: TID, WireFormat: WireU32},
	{Name: FileCreateOptions, Type: Flags32, WireFormat: WireU32, Flags: FileCreateOptionsFlags, BitField: &BitField{Mask: 0xFFFFFF}},
	{Name: FileAttributes, Type: Flags32, WireFormat: WireU32, Flags: FileAttributeFlags},
	{Name: FileShareMask, Type: Flags32, WireFormat: WireU32, Flags: FileShareModeFlags},
	{Name: FilePath, Type: DOSPath, WireFormat: WireUTF16},
	{Name: NTStatus, Type: Status},
	{Name: FileOperation, Type: Enum, Enum: fs.FileCreateDispositions},
	{Name: FileType, Type: Enum, Enum: fs.FileTypes},
	{Name: Callstack, Type: Slice},
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
	{Name: RegPath, Type: Key, WireFormat: WireUTF16},
}

var RegCreateKeyDescriptor = slices.Concat(RegistryDescriptor, []ParamInfo{{Name: Callstack, Type: Slice}})
var RegDeleteKeyDescriptor = slices.Concat(RegistryDescriptor, []ParamInfo{{Name: Callstack, Type: Slice}})
var RegSetValueDescriptor = slices.Concat(RegistryDescriptor, []ParamInfo{{Name: Callstack, Type: Slice}})
var RegDeleteValueDescriptor = slices.Concat(RegistryDescriptor, []ParamInfo{{Name: Callstack, Type: Slice}})

// 	createSymbolicLinkObjectParams = []ParamInfo{
// 		pi(params.LinkSource, params.String),
// 		pi(params.LinkTarget, params.String),
// 		pf(params.DesiredAccess, params.Flags, AccessMaskFlags),
// 		pi(params.NTStatus, params.Status),
// 		callstackParam,
// 	}

// 	registryParams = []ParamInfo{
// 		pi(params.NTStatus, params.Status),
// 		pi(params.RegKCB, params.Address),
// 		pi(params.RegPath, params.Key),
// 	}
// 	registryCallstackParams = slices.Concat(registryParams, []ParamInfo{callstackParam})
// 	regSetValueParams       = slices.Concat(registryParams, []ParamInfo{
// 		// enrichments
// 		pen(params.RegValueType, key.RegistryValueTypes),
// 		pi(params.RegData, params.Variant),
// 		callstackParam,
// 	})
// 	regSetValueInternalParams = []ParamInfo{
// 		pi(params.RegKeyHandle, params.Address),
// 		pi(params.NTStatus, params.Status),
// 		pi(params.RegPath, params.Key),
// 		pen(params.RegValueType, key.RegistryValueTypes),
// 		pi(params.RegData, params.Variant),
// 	}

// 	createFileParams = []ParamInfo{
// 		pi(params.FileIrpPtr, params.Address),
// 		pi(params.FileObject, params.Address),
// 		pi(params.ThreadID, params.TID),
// 		pf(params.FileCreateOptions, params.Flags, FileCreateOptionsFlags),
// 		pf(params.FileAttributes, params.Flags, FileAttributeFlags),
// 		pf(params.FileShareMask, params.Flags, FileShareModeFlags),
// 		pi(params.FilePath, params.DOSPath),
// 		pi(params.NTStatus, params.Status),
// 		pen(params.FileOperation, fs.FileCreateDispositions),
// 		callstackParam,
// 		// enrichments
// 		pen(params.FileType, fs.FileTypes),
// 	}
// 	fileOpEndParams = []ParamInfo{
// 		pi(params.FileIrpPtr, params.Address),
// 		pi(params.FileExtraInfo, params.Address),
// 		pi(params.NTStatus, params.Status),
// 	}
// 	fileInformationParams = []ParamInfo{
// 		pi(params.FileIrpPtr, params.Address),
// 		pi(params.FileObject, params.Address),
// 		pi(params.FileKey, params.Address),
// 		pi(params.FileExtraInfo, params.Uint64),
// 		pi(params.ThreadID, params.TID),
// 		pen(params.FileInfoClass, fs.FileInfoClasses),
// 		// enrichments
// 		pen(params.FileType, fs.FileTypes),
// 		pi(params.FilePath, params.Path),
// 	}
// 	fileInformationCallstackParams = slices.Concat(fileInformationParams, []ParamInfo{callstackParam})
// 	fileSimpleParams               = []ParamInfo{
// 		pi(params.FileIrpPtr, params.Address),
// 		pi(params.FileObject, params.Address),
// 		pi(params.FileKey, params.Address),
// 		pi(params.ThreadID, params.TID),
// 		// enrichments
// 		pen(params.FileType, fs.FileTypes),
// 		pi(params.FilePath, params.Path),
// 	}
// 	fileReadWriteParams = []ParamInfo{
// 		pi(params.FileOffset, params.Uint64),
// 		pi(params.FileIrpPtr, params.Address),
// 		pi(params.FileObject, params.Address),
// 		pi(params.FileKey, params.Address),
// 		pi(params.ThreadID, params.TID),
// 		pi(params.FileIoSize, params.Uint32),
// 		// enrichments
// 		pen(params.FileType, fs.FileTypes),
// 		pi(params.FilePath, params.Path),
// 	}
// 	enumDirectoryParams = []ParamInfo{
// 		pi(params.FileIrpPtr, params.Address),
// 		pi(params.FileObject, params.Address),
// 		pi(params.FileKey, params.Address),
// 		pi(params.ThreadID, params.TID),
// 		pen(params.FileInfoClass, fs.FileInfoClasses),
// 		pi(params.FilePath, params.String),
// 		// enrichments
// 		pi(params.FileDirectory, params.Path),
// 		pen(params.FileType, fs.FileTypes),
// 	}
// 	fileRundownParams = []ParamInfo{
// 		pi(params.FileObject, params.Address),
// 		pi(params.FilePath, params.DOSPath),
// 	}

// 	networkParams = []ParamInfo{
// 		pi(params.ProcessID, params.PID),
// 		pi(params.NetSize, params.Uint32),
// 		pi(params.NetDIP, params.IP),
// 		pi(params.NetSIP, params.IP),
// 		pi(params.NetDport, params.Port),
// 		pi(params.NetSport, params.Port),
// 		pen(params.NetL4Proto, network.ProtoNames),
// 		// enrichments
// 		pi(params.NetDportName, params.String),
// 		pi(params.NetSportName, params.String),
// 	}
// 	queryDNSParams = []ParamInfo{
// 		pi(params.DNSName, params.String),
// 		pen(params.DNSRR, DNSRecordTypes),
// 		pf(params.DNSOpts, params.Flags64, DNSOptsFlags),
// 	}
// 	replyDNSParams = slices.Concat(queryDNSParams, []ParamInfo{
// 		pen(params.DNSRcode, DNSResponseCodes),
// 		pi(params.DNSAnswers, params.Slice),
// 	})

// 	mapViewParams = []ParamInfo{
// 		pi(params.FileViewBase, params.Address),
// 		pi(params.FileKey, params.Address),
// 		pf(params.MemProtect, params.Flags, ViewProtectionFlags),
// 		pen(params.FileViewSectionType, ViewSectionTypes),
// 		pi(params.FileViewSize, params.Uint64),
// 		pi(params.FileOffset, params.Uint64),
// 		pi(params.ProcessID, params.PID),
// 		// enrichments
// 		pi(params.FilePath, params.Path),
// 		pi(params.Exe, params.Path),
// 		pi(params.ProcessName, params.String),
// 	}
// 	virtualAllocParams = []ParamInfo{
// 		pi(params.MemBaseAddress, params.Address),
// 		pi(params.MemRegionSize, params.Uint64),
// 		pi(params.ProcessID, params.PID),
// 		pf(params.MemAllocType, params.Flags, MemAllocationFlags),
// 		// enrichments
// 		pi(params.FilePath, params.DOSPath),
// 		pen(params.MemPageType, MemPageTypes),
// 		pf(params.MemProtect, params.Flags, MemProtectionFlags),
// 		pi(params.MemProtectMask, params.String),
// 		pi(params.Exe, params.Path),
// 		pi(params.ProcessName, params.String),
// 		callstackParam,
// 	}
// 	virtualFreeParams = virtualAllocParams[:len(virtualAllocParams)-1]
// )
