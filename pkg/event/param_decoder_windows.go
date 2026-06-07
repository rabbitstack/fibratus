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
	"path/filepath"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/filetime"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/rabbitstack/fibratus/pkg/util/utf16"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// ParamDecoder parses parameters from the event buffer.
type ParamDecoder struct{}

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
	e.AppendParam(params.NTStatus, params.Status, r.ReadUint32(8))
	// skip Index/InfoClass (uint32)
	e.AppendParam(params.RegKCB, params.Address, r.ReadUint64(16))
	e.AppendParam(params.RegPath, params.Key, r.ConsumeUTF16String(24))
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

	e.AppendParam(params.RegKeyHandle, params.Address, r.ReadUint64(0))
	e.AppendParam(params.NTStatus, params.Status, r.ReadUint32(8))
	e.AppendParam(params.RegPath, params.Key, filepath.Join(keyName, valueName))
	e.AppendEnum(params.RegValueType, valueType, key.RegistryValueTypes)

	if len(b) == 0 {
		return
	}

	// populate value data depending on its type
	switch valueType {
	case registry.SZ, registry.MULTI_SZ, registry.EXPAND_SZ:
		e.AppendParam(params.RegData, params.UnicodeString, utf16.BytesToString(b, binary.LittleEndian))
	case registry.BINARY:
		e.AppendParam(params.RegData, params.Binary, b)
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
		e.AppendParam(params.RegData, params.Uint32, v)
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
		e.AppendParam(params.RegData, params.Uint32, v)
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
		e.AppendParam(params.RegData, params.Uint64, v)
	}
}

// DecodeFile decodes file I/O operations such as file creation, access,
// or file metadata manipulation.
func (d *ParamDecoder) DecodeFile(r *etw.EventRecord, e *Event) {
	switch r.Header.EventDescriptor.Opcode {
	case CreateFileID:
		// typedef struct _PERFINFO_FILE_CREATE {
		//     LONG_PTR Irp;
		//     ULONG_PTR FileObject;
		//     ULONG IssuingThreadId;
		//     ULONG Options;
		//     ULONG Attributes;
		//     ULONG ShareAccess;
		//     WCHAR OpenPath[1];
		// } PERFINFO_FILE_CREATE, *PPERFINFO_FILE_CREATE;
		e.AppendParam(params.FileIrpPtr, params.Address, r.ReadUint64(0))
		e.AppendParam(params.FileObject, params.Address, r.ReadUint64(8))
		e.AppendParam(params.ThreadID, params.TID, r.ReadUint32(16))
		e.AppendParam(params.FileCreateOptions, params.Flags, r.ReadUint32(20), WithFlags(FileCreateOptionsFlags))
		e.AppendParam(params.FileAttributes, params.Flags, r.ReadUint32(24), WithFlags(FileAttributeFlags))
		e.AppendParam(params.FileShareMask, params.Flags, r.ReadUint32(28), WithFlags(FileShareModeFlags))
		e.AppendParam(params.FilePath, params.DOSPath, r.ConsumeUTF16String(32))

		// read create disposition/status from extended data items
		disposition, status := r.ReadEventHeaderFileExtendedDataItems()
		e.AppendParam(params.NTStatus, params.Status, status)
		e.AppendEnum(params.FileOperation, disposition, fs.FileCreateDispositions)
	case FileOpEndID:
		// typedef struct _PERFINFO_FILE_OPERATION_END {
		//     ULONG_PTR Irp;
		//     ULONG_PTR ExtraInformation;
		//     NTSTATUS Status;
		// } PERFINFO_FILE_OPERATION_END, *PPERFINFO_FILE_OPERATION_END;
		e.AppendParam(params.FileIrpPtr, params.Address, r.ReadUint64(0))
		e.AppendParam(params.FileExtraInfo, params.Address, r.ReadUint64(8))
		e.AppendParam(params.NTStatus, params.Status, r.ReadUint32(16))
	case MapViewFileID, UnmapViewFileID, MapFileRundownID:
		e.AppendParam(params.FileViewBase, params.Address, r.ReadUint64(0))
		e.AppendParam(params.FileKey, params.Address, r.ReadUint64(8))
		e.AppendParam(params.MemProtect, params.Flags, uint32(r.ReadUint64(16)>>32), WithFlags(ViewProtectionFlags))
		e.AppendParam(params.FileViewSectionType, params.Enum, uint32(r.ReadUint64(16)>>52), WithEnum(ViewSectionTypes))
		e.AppendParam(params.FileViewSize, params.Uint64, r.ReadUint64(24))
		e.AppendParam(params.FileOffset, params.Uint64, r.ReadUint64(32))
		e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(40))
	case SetFileInformationID, DeleteFileID, RenameFileID:
		// DeleteFile, RenameFile, and SetFileInformation share the same layout
		// typedef struct _PERFINFO_FILE_INFORMATION {
		//     ULONG_PTR Irp;
		//     ULONG_PTR FileObject;
		//     ULONG_PTR FileKey;
		//     ULONG_PTR ExtraInformation;
		//     ULONG IssuingThreadId;
		//     ULONG InfoClass;
		// } PERFINFO_FILE_INFORMATION, *PPERFINFO_FILE_INFORMATION;
		e.AppendParam(params.FileIrpPtr, params.Address, r.ReadUint64(0))
		e.AppendParam(params.FileObject, params.Address, r.ReadUint64(8))
		e.AppendParam(params.FileKey, params.Address, r.ReadUint64(16))
		e.AppendParam(params.FileExtraInfo, params.Uint64, r.ReadUint64(24))
		e.AppendParam(params.ThreadID, params.TID, r.ReadUint32(32))
		e.AppendParam(params.FileInfoClass, params.Enum, r.ReadUint32(36), WithEnum(fs.FileInfoClasses))
	case ReleaseFileID, CloseFileID:
		// typedef struct _PERFINFO_FILE_SIMPLE_OPERATION {
		//     ULONG_PTR Irp;
		//     ULONG_PTR FileObject;
		//     ULONG_PTR FileKey;
		//     ULONG IssuingThreadId;
		// } PERFINFO_FILE_SIMPLE_OPERATION, *PPERFINFO_FILE_SIMPLE_OPERATION;
		e.AppendParam(params.FileIrpPtr, params.Address, r.ReadUint64(0))
		e.AppendParam(params.FileObject, params.Address, r.ReadUint64(8))
		e.AppendParam(params.FileKey, params.Address, r.ReadUint64(16))
		e.AppendParam(params.ThreadID, params.TID, r.ReadUint32(24))
	case ReadFileID, WriteFileID:
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
		e.AppendParam(params.FileOffset, params.Uint64, r.ReadUint64(0))
		e.AppendParam(params.FileIrpPtr, params.Address, r.ReadUint64(8))
		e.AppendParam(params.FileObject, params.Address, r.ReadUint64(16))
		e.AppendParam(params.FileKey, params.Address, r.ReadUint64(24))
		e.AppendParam(params.ThreadID, params.TID, r.ReadUint32(32))
		e.AppendParam(params.FileIoSize, params.Uint32, r.ReadUint32(34))
	case EnumDirectoryID:
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
		e.AppendParam(params.FileIrpPtr, params.Address, r.ReadUint64(0))
		e.AppendParam(params.FileObject, params.Address, r.ReadUint64(8))
		e.AppendParam(params.FileKey, params.Address, r.ReadUint64(16))
		e.AppendParam(params.ThreadID, params.TID, r.ReadUint32(24))
		// skip Length (uint32)
		e.AppendParam(params.FileInfoClass, params.Enum, r.ReadUint32(32), WithEnum(fs.FileInfoClasses))
		// skip FileIndex (uint32)
		e.AppendParam(params.FilePath, params.UnicodeString, r.ConsumeUTF16String(40))
	case FileRundownID:
		e.AppendParam(params.FileObject, params.Address, r.ReadUint64(0))
		e.AppendParam(params.FilePath, params.DOSPath, r.ConsumeUTF16String(8))
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

	e.AppendParam(params.ProcessObject, params.Address, r.ReadUint64(0))
	e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(8))
	e.AppendParam(params.ProcessParentID, params.PID, r.ReadUint32(12))
	e.AppendParam(params.SessionID, params.Uint32, r.ReadUint32(16))
	e.AppendParam(params.ExitStatus, params.Status, r.ReadUint32(20))
	e.AppendParam(params.DTB, params.Address, r.ReadUint64(24))
	e.AppendParam(params.ProcessFlags, params.Flags, r.ReadUint32(32), WithFlags(PsCreationFlags))
	e.AppendParam(params.UserSID, params.WbemSID, sid)
	e.AppendParam(params.ProcessName, params.AnsiString, name)
	e.AppendParam(params.Cmdline, params.UnicodeString, cmdline)
	e.AppendParam(params.ProcessRealParentID, params.PID, r.Header.ProcessID)
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
	e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(0))
	e.AppendParam(params.ProcessObject, params.Address, r.ReadUint64(4))

	createTime := windows.NsecToFiletime(int64(r.ReadUint64(12)))
	e.AppendParam(params.StartTime, params.Time, filetime.ToEpoch(uint64(createTime.Nanoseconds())))

	e.AppendParam(params.ProcessParentID, params.PID, r.ReadUint32(20))
	// skip ParentProcessSequenceNumber (uint64)
	e.AppendParam(params.SessionID, params.Uint32, r.ReadUint32(32))
	e.AppendParam(params.ProcessFlags, params.Flags, r.ReadUint32(36), WithFlags(PsCreationFlags))
	e.AppendParam(params.ProcessTokenElevationType, params.Enum, r.ReadUint32(40), WithEnum(PsTokenElevationTypes))
	e.AppendParam(params.ProcessTokenIsElevated, params.Bool, r.ReadUint32(44) > 0)

	tokenMandatoryLabel, _ := r.ReadSID(48, false) // integrity level SID size is 12 bytes
	e.AppendParam(params.ProcessTokenIntegrityLevel, params.SID, tokenMandatoryLabel)

	exe, _ := r.ReadNTUnicodeString(60)
	e.AppendParam(params.Exe, params.DOSPath, exe)
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
	e.AppendParam(params.ModuleBase, params.Address, r.ReadUint64(0))
	e.AppendParam(params.ModuleSize, params.Uint64, r.ReadUint64(8))
	e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(16))
	e.AppendParam(params.ModuleCheckSum, params.Uint32, r.ReadUint32(20))
	// skip TimeDateStamp (uint32)
	e.AppendParam(params.ModuleSignatureLevel, params.Enum, uint32(r.ReadByte(28)), WithEnum(signature.Levels))
	e.AppendParam(params.ModuleSignatureType, params.Enum, uint32(r.ReadByte(29)), WithEnum(signature.Types))
	// skip Reserved0 (uint8)
	e.AppendParam(params.ModuleDefaultBase, params.Address, r.ReadUint64(32))
	// skip Reserved1-Reserved4 (uint32 * 4)
	const offset = 56
	e.AppendParam(params.ModulePath, params.DOSPath, r.ConsumeUTF16String(offset))
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
	e.AppendParam(params.ModuleBase, params.Address, r.ReadUint64(0))
	e.AppendParam(params.ModuleSize, params.Uint64, r.ReadUint64(8))
	e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(16))
	e.AppendParam(params.ModuleCheckSum, params.Uint32, r.ReadUint32(20))
	// skip TimeDateStamp (uint32)
	e.AppendParam(params.ModuleDefaultBase, params.Address, r.ReadUint64(28))
	e.AppendParam(params.ModulePath, params.DOSPath, r.ConsumeUTF16String(36))
}

// DecodeOpenProcess parses the event payload for OpenProcess events.
func (d *ParamDecoder) DecodeOpenProcess(r *etw.EventRecord, e *Event) {
	e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(0))
	e.AppendParam(params.DesiredAccess, params.Flags, r.ReadUint32(4), WithFlags(PsAccessRightFlags))
	e.AppendParam(params.NTStatus, params.Status, r.ReadUint32(8))
	e.AppendParam(params.Callstack, params.Slice, r.Callstack())
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
	e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(0))
	e.AppendParam(params.ThreadID, params.TID, r.ReadUint32(4))
	e.AppendParam(params.KstackBase, params.Address, r.ReadUint64(8))
	e.AppendParam(params.KstackLimit, params.Address, r.ReadUint64(16))
	e.AppendParam(params.UstackBase, params.Address, r.ReadUint64(24))
	e.AppendParam(params.UstackLimit, params.Address, r.ReadUint64(32))
	// skip StartAddr64 (uint64)
	e.AppendParam(params.StartAddress, params.Address, r.ReadUint64(48))
	e.AppendParam(params.TEB, params.Address, r.ReadUint64(56))
	// skip SubProcessTag (uint32)
	e.AppendParam(params.BasePrio, params.Uint8, r.ReadByte(68))
	e.AppendParam(params.PagePrio, params.Uint8, r.ReadByte(69))
	e.AppendParam(params.IOPrio, params.Uint8, r.ReadByte(70))
}

// DecodeOpenThread decodes the payload for the OpenThread event.
func (d *ParamDecoder) DecodeOpenThread(r *etw.EventRecord, e *Event) {
	e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(0))
	e.AppendParam(params.ThreadID, params.TID, r.ReadUint32(4))
	e.AppendParam(params.DesiredAccess, params.Flags, r.ReadUint32(8), WithFlags(ThreadAccessRightFlags))
	e.AppendParam(params.NTStatus, params.Status, r.ReadUint32(12))
	e.AppendParam(params.Callstack, params.Slice, r.Callstack())
}

// DecodeSetThreadContext decodes the payload for the SetThreadContext event.
func (d *ParamDecoder) DecodeSetThreadContext(r *etw.EventRecord, e *Event) {
	e.AppendParam(params.NTStatus, params.Status, r.ReadUint32(0))
	e.AppendParam(params.Callstack, params.Slice, r.Callstack())
}

// DecodeThreadpool decodes payloads for thread pool events.
func (d *ParamDecoder) DecodeThreadpool(r *etw.EventRecord, e *Event) {
	switch r.Header.EventDescriptor.Opcode {
	case SubmitThreadpoolWorkID, SubmitThreadpoolCallbackID:
		// typedef struct _ETW_TP_EVENT_CALLBACK_ENQUEUE {
		//     PVOID PoolId;                   // Pool Identifier
		//     PVOID TaskId;                   // Task Identifier
		//     PVOID Callback;                 // Callback Function
		//     PVOID Context;                  // Callback Context
		//     PVOID SubProcessTag;            // Sub-components in a process
		// } ETW_TP_EVENT_CALLBACK_ENQUEUE, *PETW_TP_EVENT_CALLBACK_ENQUEUE
		e.AppendParam(params.ThreadpoolPoolID, params.Address, r.ReadUint64(0))
		e.AppendParam(params.ThreadpoolTaskID, params.Address, r.ReadUint64(8))
		e.AppendParam(params.ThreadpoolCallback, params.Address, r.ReadUint64(16))
		e.AppendParam(params.ThreadpoolContext, params.Address, r.ReadUint64(24))
		e.AppendParam(params.ThreadpoolSubprocessTag, params.Address, r.ReadUint64(32))
	case SetThreadpoolTimerID:
		// typedef struct _ETW_TP_EVENT_TIMER_SET {
		//     LONG64 DueTime;                 // Due time
		//     PVOID SubQueue;                 // Sub Queue to be inserted
		//     PVOID Timer;                    // Timer to be set
		//     ULONG Period;                   // period of the timer
		//     ULONG WindowLength;             // Tolerate period
		//     ULONG Absolute;                 // An absolute timer or relative timer
		// } ETW_TP_EVENT_TIMER_SET, *PETW_TP_EVENT_TIMER_SET;
		e.AppendParam(params.ThreadpoolTimerDuetime, params.Uint64, r.ReadUint64(0))
		e.AppendParam(params.ThreadpoolTimerSubqueue, params.Address, r.ReadUint64(8))
		e.AppendParam(params.ThreadpoolTimer, params.Address, r.ReadUint64(16))
		e.AppendParam(params.ThreadpoolTimerPeriod, params.Uint32, r.ReadUint32(24))
		e.AppendParam(params.ThreadpoolTimerWindow, params.Uint32, r.ReadUint32(28))
		e.AppendParam(params.ThreadpoolTimerAbsolute, params.Bool, r.ReadUint32(32) > 0)
	}
}

// DecodeHandle decodes events for handle creation/disposition events.
func (d *ParamDecoder) DecodeHandle(r *etw.EventRecord, e *Event) {
	switch r.Header.EventDescriptor.Opcode {
	case CreateHandleID, CloseHandleID:
		// typedef struct _ETW_CREATE_HANDLE_EVENT {
		//     PVOID Object;
		//     ULONG Handle;
		//     USHORT ObjectType;
		// } ETW_CREATE_HANDLE_EVENT, *PETW_CREATE_HANDLE_EVENT;
		e.AppendParam(params.HandleObject, params.Address, r.ReadUint64(0))
		e.AppendParam(params.HandleID, params.Uint32, r.ReadUint32(8))
		e.AppendParam(params.HandleObjectTypeID, params.HandleType, r.ReadUint16(12))
		if r.BufferLen >= 16 {
			e.AppendParam(params.HandleObjectName, params.UnicodeString, r.ConsumeUTF16String(14))
		}
	case DuplicateHandleID:
		// typedef struct _ETW_DUPLICATE_HANDLE_EVENT {
		//     PVOID Object;
		//     ULONG SourceHandle;
		//     ULONG TargetHandle;
		//     ULONG TargetProcessId;
		//     USHORT ObjectType;
		//     ULONG SourceProcessId;
		// } ETW_DUPLICATE_HANDLE_EVENT, *PETW_DUPLICATE_HANDLE_EVENT;
		e.AppendParam(params.HandleObject, params.Address, r.ReadUint64(0))
		e.AppendParam(params.HandleSourceID, params.Uint32, r.ReadUint32(8))
		e.AppendParam(params.HandleID, params.Uint32, r.ReadUint32(12))
		e.AppendParam(params.TargetProcessID, params.PID, r.ReadUint32(16))
		e.AppendParam(params.HandleObjectTypeID, params.HandleType, r.ReadUint16(20))
		e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(22))
	}
}

// DecodeCreateSymbolicLinkObject decodes the payload for the CreateSymbolicLinkObject event.
func (d *ParamDecoder) DecodeCreateSymbolicLinkObject(r *etw.EventRecord, e *Event) {
	source, offset := r.ReadUTF16String(0)
	target, offset := r.ReadUTF16String(offset)
	e.AppendParam(params.LinkSource, params.UnicodeString, source)
	e.AppendParam(params.LinkTarget, params.UnicodeString, target)
	e.AppendParam(params.DesiredAccess, params.Flags, r.ReadUint32(offset), WithFlags(AccessMaskFlags))
	e.AppendParam(params.NTStatus, params.Status, r.ReadUint32(offset+4))
	e.AppendParam(params.Callstack, params.Slice, r.Callstack())
}

// DecodeStackwalk decodes stackwalk event parameters including frame return addresses.
func (d *ParamDecoder) DecodeStackwalk(r *etw.EventRecord, e *Event) {
	// typedef struct _STACK_WALK_EVENT_DATA {
	//         ULONGLONG   TimeStamp;
	//         ULONG       ProcessId;
	//         ULONG       ThreadId;
	//         PVOID       Addresses[1]; // Address of captured Stack address
	// } STACK_WALK_EVENT_DATA, *PSTACK_WALK_EVENT_DATA;

	// Skip TimeStamp (uint64)
	e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(8))
	e.AppendParam(params.ThreadID, params.TID, r.ReadUint32(12))

	var n uint16
	var offset uint16 = 16

	frames := (r.BufferLen - offset) / 8
	callstack := make([]va.Address, frames)
	for n < frames {
		callstack[n] = va.Address(r.ReadUint64(offset))
		offset += 8
		n++
	}
	e.AppendParam(params.Callstack, params.Slice, callstack)
}

// DecodeMemory decodes memory event payloads.
func (d *ParamDecoder) DecodeMemory(r *etw.EventRecord, e *Event) {
	// typedef struct _PERFINFO_VIRTUAL_ALLOC {
	//     PVOID CapturedBase;
	//     SIZE_T CapturedRegionSize;
	//     ULONG ProcessId;
	//     ULONG Flags;
	// } PERFINFO_VIRTUAL_ALLOC, *PPERFINFO_VIRTUAL_ALLOC;
	e.AppendParam(params.MemBaseAddress, params.Address, r.ReadUint64(0))
	e.AppendParam(params.MemRegionSize, params.Uint64, r.ReadUint64(8))
	e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(16))
	e.AppendParam(params.MemAllocType, params.Flags, r.ReadUint32(20), WithFlags(MemAllocationFlags))
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
	e.AppendParam(params.ProcessID, params.PID, r.ReadUint32(0))
	e.AppendParam(params.NetSize, params.Uint32, r.ReadUint32(4))

	switch r.Header.EventDescriptor.Opcode {
	case AcceptTCPv6ID, ConnectTCPv6ID, ReconnectTCPv6ID, RetransmitTCPv6ID,
		DisconnectTCPv6ID, SendV6ID, RecvV6ID:
		e.AppendParam(params.NetDIP, params.IPv6, r.ReadBytes(8, 16))
		e.AppendParam(params.NetSIP, params.IPv6, r.ReadBytes(24, 16))
		e.AppendParam(params.NetDport, params.Port, r.ReadUint16(40))
		e.AppendParam(params.NetSport, params.Port, r.ReadUint16(42))
	default:
		e.AppendParam(params.NetDIP, params.IPv4, r.ReadUint32(8))
		e.AppendParam(params.NetSIP, params.IPv4, r.ReadUint32(12))
		e.AppendParam(params.NetDport, params.Port, r.ReadUint16(16))
		e.AppendParam(params.NetSport, params.Port, r.ReadUint16(18))
	}
}

// DecodeDNS decodes DNS query/reply event payloads.
func (d *ParamDecoder) DecodeDNS(r *etw.EventRecord, e *Event) {
	name, offset := r.ReadUTF16String(0)
	e.AppendParam(params.DNSName, params.UnicodeString, name)
	e.AppendParam(params.DNSRR, params.Enum, r.ReadUint32(offset), WithEnum(DNSRecordTypes))
	e.AppendParam(params.DNSOpts, params.Flags64, r.ReadUint64(offset+4), WithFlags(DNSOptsFlags))

	if r.Header.EventDescriptor.ID == ReplyDNSID {
		e.AppendParam(params.DNSRcode, params.Enum, r.ReadUint32(offset+12), WithEnum(DNSResponseCodes))
		answers := strings.Split(sanitizeDNSAnswers(r.ConsumeUTF16String(offset+16)), ";")
		e.AppendParam(params.DNSAnswers, params.Slice, answers)
	}
}

// sanitizeDNSAnswers removes the "type" string from DNS answers.
func sanitizeDNSAnswers(answers string) string {
	return strings.ReplaceAll(answers, "type: 5 ", "")
}
