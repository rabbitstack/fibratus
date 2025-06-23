/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/filetime"
	"github.com/rabbitstack/fibratus/pkg/util/ip"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/rabbitstack/fibratus/pkg/util/ntstatus"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"golang.org/x/sys/windows"
	"net"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

// unknownKeysCount counts the number of times the registry key failed to convert from native format
var unknownKeysCount = expvar.NewInt("registry.unknown.keys.count")

// NewParam creates a new event parameter. Since the parameter type is already categorized,
// we can coerce the value to the appropriate representation (e.g. hex, IP address)
func NewParam(name string, typ params.Type, value params.Value, options ...ParamOption) *Param {
	var opts paramOpts
	for _, opt := range options {
		opt(&opts)
	}
	var v params.Value
	switch typ {
	case params.IPv4:
		v = ip.ToIPv4(value.(uint32))
	case params.IPv6:
		v = ip.ToIPv6(value.([]byte))
	case params.Port:
		v = windows.Ntohs(value.(uint16))
	default:
		v = value
	}
	return &Param{Name: name, Type: typ, Value: v, Flags: opts.flags, Enum: opts.enum}
}

var devMapper = fs.NewDevMapper()

// String returns the string representation of the parameter value.
func (p Param) String() string {
	if p.Value == nil {
		return ""
	}
	switch p.Type {
	case params.UnicodeString, params.AnsiString, params.Path:
		return p.Value.(string)
	case params.SID, params.WbemSID:
		sid, err := getSID(&p)
		if err != nil {
			return ""
		}
		if p.Name == params.ProcessIntegrityLevel {
			return sys.RidToString(sid)
		}
		return sid.String()
	case params.DOSPath:
		return devMapper.Convert(p.Value.(string))
	case params.Key:
		rootKey, keyName := key.Format(p.Value.(string))
		if keyName != "" && rootKey != key.Invalid {
			return rootKey.String() + "\\" + keyName
		}
		if rootKey != key.Invalid {
			return rootKey.String()
		}
		unknownKeysCount.Add(1)
		return keyName
	case params.HandleType:
		return htypes.ConvertTypeIDToName(p.Value.(uint16))
	case params.Status:
		v, ok := p.Value.(uint32)
		if !ok {
			return ""
		}
		return ntstatus.FormatMessage(v)
	case params.Address:
		v, ok := p.Value.(uint64)
		if !ok {
			return ""
		}
		return va.Address(v).String()
	case params.Int8:
		return strconv.Itoa(int(p.Value.(int8)))
	case params.Uint8:
		return strconv.Itoa(int(p.Value.(uint8)))
	case params.Int16:
		return strconv.Itoa(int(p.Value.(int16)))
	case params.Uint16, params.Port:
		return strconv.Itoa(int(p.Value.(uint16)))
	case params.Uint32, params.PID, params.TID:
		return strconv.Itoa(int(p.Value.(uint32)))
	case params.Int32:
		return strconv.Itoa(int(p.Value.(int32)))
	case params.Uint64:
		return strconv.FormatUint(p.Value.(uint64), 10)
	case params.Int64:
		return strconv.Itoa(int(p.Value.(int64)))
	case params.IPv4, params.IPv6:
		return p.Value.(net.IP).String()
	case params.Bool:
		return strconv.FormatBool(p.Value.(bool))
	case params.Float:
		return strconv.FormatFloat(float64(p.Value.(float32)), 'f', 6, 32)
	case params.Double:
		return strconv.FormatFloat(p.Value.(float64), 'f', 6, 64)
	case params.Time:
		return p.Value.(time.Time).String()
	case params.Enum:
		if p.Enum == nil {
			return ""
		}
		e := p.Value
		v, ok := e.(uint32)
		if !ok {
			return ""
		}
		return p.Enum[v]
	case params.Flags, params.Flags64:
		if p.Flags == nil {
			return ""
		}
		f := p.Value
		switch v := f.(type) {
		case uint32:
			return p.Flags.String(uint64(v))
		case uint64:
			return p.Flags.String(v)
		default:
			return ""
		}
	case params.Slice:
		switch slice := p.Value.(type) {
		case []string:
			return strings.Join(slice, ",")
		default:
			return fmt.Sprintf("%v", slice)
		}
	case params.Binary:
		return string(p.Value.([]byte))
	}
	return fmt.Sprintf("%v", p.Value)
}

// GetSID returns the raw SID (Security Identifier) parameter as
// typed representation on which various operations can be performed,
// such as converting the SID to string or resolving username/domain.
func (pars Params) GetSID() (*windows.SID, error) {
	par, err := pars.findParam(params.UserSID)
	if err != nil {
		return nil, err
	}
	return getSID(par)
}

func getSID(param *Param) (*windows.SID, error) {
	sid, ok := param.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("unable to type cast %q parameter to []byte value", param.Name)
	}
	if sid == nil {
		return nil, fmt.Errorf("sid linked to parameter %s is empty", param.Name)
	}
	b := uintptr(unsafe.Pointer(&sid[0]))
	if param.Type == params.WbemSID {
		// a WBEM SID is actually a TOKEN_USER structure followed
		// by the SID, so we have to double the pointer size
		b += uintptr(8 * 2)
	}
	return (*windows.SID)(unsafe.Pointer(b)), nil
}

// MustGetSID returns the SID (Security Identifier) event parameter
// or panics if an error occurs.
func (pars Params) MustGetSID() *windows.SID {
	sid, err := pars.GetSID()
	if err != nil {
		panic(err)
	}
	return sid
}

// produceParams parses the event binary layout to extract
// the parameters. Each event is annotated with the schema
// version number which helps us determine when the event
// schema changes in order to parse new fields.
func (e *Event) produceParams(evt *etw.EventRecord) {
	switch e.Type {
	case ProcessRundown, CreateProcess, TerminateProcess:
		var (
			kproc      uint64
			pid, ppid  uint32
			sessionID  uint32
			exitStatus uint32
			dtb        uint64
			flags      uint32
			sid        []byte
			name       string
			cmdline    string
		)
		var offset uint16
		var soffset uint16
		var noffset uint16
		if evt.Version() >= 1 {
			pid = evt.ReadUint32(8)
			ppid = evt.ReadUint32(12)
			sessionID = evt.ReadUint32(16)
			exitStatus = evt.ReadUint32(20)
		}
		if evt.Version() >= 2 {
			kproc = evt.ReadUint64(0)
		}
		if evt.Version() >= 3 {
			dtb = evt.ReadUint64(24)
		}
		if evt.Version() >= 4 {
			flags = evt.ReadUint32(32)
		}
		switch {
		case evt.Version() >= 4:
			offset = 36
		case evt.Version() >= 3:
			offset = 32
		default:
			offset = 24
		}
		sid, soffset = evt.ReadSID(offset, true)
		name, noffset = evt.ReadAnsiString(soffset)
		cmdline, _ = evt.ReadUTF16String(soffset + noffset)
		e.AppendParam(params.ProcessObject, params.Address, kproc)
		e.AppendParam(params.ProcessID, params.PID, pid)
		e.AppendParam(params.ProcessParentID, params.PID, ppid)
		e.AppendParam(params.ProcessRealParentID, params.PID, evt.Header.ProcessID)
		e.AppendParam(params.SessionID, params.Uint32, sessionID)
		e.AppendParam(params.ExitStatus, params.Status, exitStatus)
		e.AppendParam(params.DTB, params.Address, dtb)
		e.AppendParam(params.ProcessFlags, params.Flags, flags, WithFlags(PsCreationFlags))
		e.AppendParam(params.UserSID, params.WbemSID, sid)
		e.AppendParam(params.ProcessName, params.AnsiString, name)
		e.AppendParam(params.Cmdline, params.UnicodeString, cmdline)
	case CreateProcessInternal, ProcessRundownInternal:
		var (
			pid                 uint32
			createTime          windows.Filetime
			ppid                uint32
			sessionID           uint32
			flags               uint32
			tokenElevationType  uint32
			tokenIsElevated     uint32
			tokenMandatoryLabel []byte
			exe                 string
		)

		pid = evt.ReadUint32(0)

		if (e.IsCreateProcessInternal() && evt.Version() >= 3) || (e.IsProcessRundownInternal() && evt.Version() >= 1) {
			createTime = windows.NsecToFiletime(int64(evt.ReadUint64(12))) // skip sequence number (8 bytes)

			ppid = evt.ReadUint32(20)
			sessionID = evt.ReadUint32(32) // skip parent sequence number (8 bytes)
			flags = evt.ReadUint32(36)
			tokenElevationType = evt.ReadUint32(40)
			tokenIsElevated = evt.ReadUint32(44)

			tokenMandatoryLabel, _ = evt.ReadSID(48, false) // integrity level SID size is 12 bytes

			exe, _ = evt.ReadNTUnicodeString(60)
		} else {
			createTime = windows.NsecToFiletime(int64(evt.ReadUint64(8)))
			ppid = evt.ReadUint32(16)
			sessionID = evt.ReadUint32(20)
			flags = evt.ReadUint32(24)
			exe, _ = evt.ReadNTUnicodeString(28)
		}

		e.AppendParam(params.ProcessID, params.PID, pid)
		e.AppendParam(params.StartTime, params.Time, filetime.ToEpoch(uint64(createTime.Nanoseconds())))
		e.AppendParam(params.ProcessParentID, params.PID, ppid)
		e.AppendParam(params.SessionID, params.Uint32, sessionID)
		e.AppendParam(params.ProcessFlags, params.Flags, flags, WithFlags(PsCreationFlags))
		e.AppendParam(params.ProcessTokenElevationType, params.Enum, tokenElevationType, WithEnum(PsTokenElevationTypes))
		e.AppendParam(params.ProcessTokenIsElevated, params.Bool, tokenIsElevated > 0)
		e.AppendParam(params.ProcessIntegrityLevel, params.SID, tokenMandatoryLabel)
		e.AppendParam(params.Exe, params.DOSPath, exe)
	case OpenProcess:
		processID := evt.ReadUint32(0)
		desiredAccess := evt.ReadUint32(4)
		status := evt.ReadUint32(8)
		e.AppendParam(params.ProcessID, params.PID, processID)
		e.AppendParam(params.DesiredAccess, params.Flags, desiredAccess, WithFlags(PsAccessRightFlags))
		e.AppendParam(params.NTStatus, params.Status, status)

		// append callstack for interested flags
		if desiredAccess == AllAccess || ((desiredAccess & windows.PROCESS_VM_READ) != 0) || ((desiredAccess & windows.PROCESS_VM_WRITE) != 0) ||
			((desiredAccess & windows.PROCESS_VM_OPERATION) != 0) || ((desiredAccess & windows.PROCESS_DUP_HANDLE) != 0) ||
			((desiredAccess & windows.PROCESS_TERMINATE) != 0) || ((desiredAccess & windows.PROCESS_CREATE_PROCESS) != 0) ||
			((desiredAccess & windows.PROCESS_CREATE_THREAD) != 0) || ((desiredAccess & windows.PROCESS_SET_INFORMATION) != 0) {
			e.AppendParam(params.Callstack, params.Slice, evt.Callstack())
		}
	case CreateThread, TerminateThread, ThreadRundown:
		var (
			pid            uint32
			tid            uint32
			kstack, klimit uint64
			ustack, ulimit uint64
			startAddress   uint64
			teb            uint64
			basePrio       uint8
			pagePrio       uint8
			ioPrio         uint8
		)
		if evt.Version() >= 1 {
			pid = evt.ReadUint32(0)
			tid = evt.ReadUint32(4)
		} else {
			pid = evt.ReadUint32(4)
			tid = evt.ReadUint32(0)
		}
		if evt.Version() >= 2 {
			kstack = evt.ReadUint64(8)
			klimit = evt.ReadUint64(16)
			ustack = evt.ReadUint64(24)
			ulimit = evt.ReadUint64(32)
			startAddress = evt.ReadUint64(48)
			teb = evt.ReadUint64(56)
		}
		if evt.Version() >= 3 {
			basePrio = evt.ReadByte(69)
			pagePrio = evt.ReadByte(70)
			ioPrio = evt.ReadByte(71)
		}
		e.AppendParam(params.ProcessID, params.PID, pid)
		e.AppendParam(params.ThreadID, params.TID, tid)
		e.AppendParam(params.KstackBase, params.Address, kstack)
		e.AppendParam(params.KstackLimit, params.Address, klimit)
		e.AppendParam(params.UstackBase, params.Address, ustack)
		e.AppendParam(params.UstackLimit, params.Address, ulimit)
		e.AppendParam(params.StartAddress, params.Address, startAddress)
		e.AppendParam(params.TEB, params.Address, teb)
		e.AppendParam(params.BasePrio, params.Uint8, basePrio)
		e.AppendParam(params.PagePrio, params.Uint8, pagePrio)
		e.AppendParam(params.IOPrio, params.Uint8, ioPrio)
	case OpenThread:
		processID := evt.ReadUint32(0)
		threadID := evt.ReadUint32(4)
		desiredAccess := evt.ReadUint32(8)
		status := evt.ReadUint32(12)
		e.AppendParam(params.ProcessID, params.PID, processID)
		e.AppendParam(params.ThreadID, params.TID, threadID)
		e.AppendParam(params.DesiredAccess, params.Flags, desiredAccess, WithFlags(ThreadAccessRightFlags))
		e.AppendParam(params.NTStatus, params.Status, status)

		// append callstack for interested flags
		if desiredAccess == AllAccess || ((desiredAccess & windows.THREAD_SET_CONTEXT) != 0) || ((desiredAccess & windows.THREAD_SET_THREAD_TOKEN) != 0) ||
			((desiredAccess & windows.THREAD_IMPERSONATE) != 0) || ((desiredAccess & windows.THREAD_DIRECT_IMPERSONATION) != 0) ||
			((desiredAccess & windows.THREAD_SUSPEND_RESUME) != 0) || ((desiredAccess & windows.THREAD_TERMINATE) != 0) ||
			((desiredAccess & windows.THREAD_SET_INFORMATION) != 0) {
			e.AppendParam(params.Callstack, params.Slice, evt.Callstack())
		}
	case SetThreadContext:
		status := evt.ReadUint32(0)
		e.AppendParam(params.NTStatus, params.Status, status)
		if evt.HasStackTrace() {
			e.AppendParam(params.Callstack, params.Slice, evt.Callstack())
		}
	case CreateHandle, CloseHandle:
		object := evt.ReadUint64(0)
		handleID := evt.ReadUint32(8)
		typeID := evt.ReadUint16(12)
		var handleName string
		if evt.BufferLen >= 16 {
			handleName = evt.ConsumeUTF16String(14)
		}
		e.AppendParam(params.HandleObject, params.Address, object)
		e.AppendParam(params.HandleID, params.Uint32, handleID)
		e.AppendParam(params.HandleObjectTypeID, params.HandleType, typeID)
		e.AppendParam(params.HandleObjectName, params.UnicodeString, handleName)
	case DuplicateHandle:
		object := evt.ReadUint64(0)
		srcHandleID := evt.ReadUint32(8)
		dstHandleID := evt.ReadUint32(12)
		targetPID := evt.ReadUint32(16)
		typeID := evt.ReadUint16(20)
		sourcePID := evt.ReadUint32(22)
		e.AppendParam(params.HandleObject, params.Address, object)
		e.AppendParam(params.HandleID, params.Uint32, dstHandleID)
		e.AppendParam(params.HandleSourceID, params.Uint32, srcHandleID)
		e.AppendParam(params.HandleObjectTypeID, params.HandleType, typeID)
		e.AppendParam(params.ProcessID, params.PID, sourcePID)
		e.AppendParam(params.TargetProcessID, params.PID, targetPID)
	case LoadImage, UnloadImage, ImageRundown:
		var (
			pid               uint32
			checksum          uint32
			defaultBase       uint64
			filename          string
			sigLevel, sigType uint8
		)
		var offset uint16
		imageBase := evt.ReadUint64(0)
		imageSize := evt.ReadUint64(8)
		if evt.Version() >= 1 {
			pid = evt.ReadUint32(16)
		}
		if evt.Version() >= 2 {
			checksum = evt.ReadUint32(20)
			defaultBase = evt.ReadUint64(30)
		}
		if evt.Version() >= 3 {
			sigLevel = evt.ReadByte(28)
			sigType = evt.ReadByte(29)
			defaultBase = evt.ReadUint64(32)
		}
		switch {
		case evt.Version() >= 3:
			offset = 56
		case evt.Version() >= 2:
			offset = 54
		case evt.Version() >= 1:
			offset = 20
		default:
			offset = 16
		}
		filename = evt.ConsumeUTF16String(offset)
		e.AppendParam(params.ProcessID, params.PID, pid)
		e.AppendParam(params.ImageCheckSum, params.Uint32, checksum)
		e.AppendParam(params.ImageDefaultBase, params.Address, defaultBase)
		e.AppendParam(params.ImageBase, params.Address, imageBase)
		e.AppendParam(params.ImageSize, params.Uint64, imageSize)
		e.AppendParam(params.ImagePath, params.DOSPath, filename)
		e.AppendParam(params.ImageSignatureLevel, params.Enum, uint32(sigLevel), WithEnum(signature.Levels))
		e.AppendParam(params.ImageSignatureType, params.Enum, uint32(sigType), WithEnum(signature.Types))
	case LoadImageInternal:
		var (
			pid         uint32
			checksum    uint32
			defaultBase uint64
			imageBase   uint64
			imageSize   uint64
			filename    string
		)

		imageBase = evt.ReadUint64(0)
		imageSize = evt.ReadUint64(8)
		pid = evt.ReadUint32(16)
		checksum = evt.ReadUint32(20)
		defaultBase = evt.ReadUint64(28) // skip timestamp (4 bytes)
		filename = evt.ConsumeUTF16String(36)

		e.AppendParam(params.ProcessID, params.PID, pid)
		e.AppendParam(params.ImageCheckSum, params.Uint32, checksum)
		e.AppendParam(params.ImageDefaultBase, params.Address, defaultBase)
		e.AppendParam(params.ImageBase, params.Address, imageBase)
		e.AppendParam(params.ImageSize, params.Uint64, imageSize)
		e.AppendParam(params.ImagePath, params.DOSPath, filename)
	case RegOpenKey, RegCloseKey,
		RegCreateKCB, RegDeleteKCB,
		RegKCBRundown, RegCreateKey,
		RegDeleteKey, RegDeleteValue,
		RegQueryKey, RegQueryValue,
		RegSetValue:
		var (
			status    uint32
			keyHandle uint64
			keyName   string
		)
		if evt.Version() >= 2 {
			status = evt.ReadUint32(8)
			keyHandle = evt.ReadUint64(16)
		} else {
			status = evt.ReadUint32(0)
			keyHandle = evt.ReadUint64(4)
		}
		if evt.Version() >= 1 {
			keyName = evt.ConsumeUTF16String(24)
		} else {
			keyName = evt.ConsumeUTF16String(20)
		}
		e.AppendParam(params.RegKeyHandle, params.Address, keyHandle)
		e.AppendParam(params.RegPath, params.Key, keyName)
		e.AppendParam(params.NTStatus, params.Status, status)
	case CreateFile:
		var (
			irp            uint64
			fileObject     uint64
			tid            uint32
			createOptions  uint32
			fileAttributes uint32
			shareAccess    uint32
			filename       string
		)
		if evt.Version() >= 2 {
			irp = evt.ReadUint64(0)
			fileObject = evt.ReadUint64(8)
			tid = evt.ReadUint32(16)
			createOptions = evt.ReadUint32(20)
			fileAttributes = evt.ReadUint32(24)
			shareAccess = evt.ReadUint32(28)
			filename = evt.ConsumeUTF16String(32)
		} else {
			fileObject = evt.ReadUint64(0)
			filename = evt.ConsumeUTF16String(8)
		}
		e.AppendParam(params.FileIrpPtr, params.Address, irp)
		e.AppendParam(params.FileObject, params.Address, fileObject)
		e.AppendParam(params.ThreadID, params.TID, tid)
		e.AppendParam(params.FileShareMask, params.Flags, shareAccess, WithFlags(FileShareModeFlags))
		e.AppendParam(params.FileAttributes, params.Flags, fileAttributes, WithFlags(FileAttributeFlags))
		e.AppendParam(params.FileCreateOptions, params.Flags, createOptions, WithFlags(FileCreateOptionsFlags))
		e.AppendParam(params.FilePath, params.DOSPath, filename)
	case FileOpEnd:
		var (
			irp       uint64
			extraInfo uint64
			status    uint32
		)
		if evt.Version() >= 2 {
			irp = evt.ReadUint64(0)
			extraInfo = evt.ReadUint64(8)
			status = evt.ReadUint32(16)
		}
		e.AppendParam(params.FileIrpPtr, params.Address, irp)
		e.AppendParam(params.FileExtraInfo, params.Address, extraInfo)
		e.AppendParam(params.NTStatus, params.Status, status)
	case FileRundown:
		var (
			fileObject uint64
			filename   string
		)
		if evt.Version() >= 2 {
			fileObject = evt.ReadUint64(0)
			filename = evt.ConsumeUTF16String(8)
		}
		e.AppendParam(params.FileObject, params.Address, fileObject)
		e.AppendParam(params.FilePath, params.DOSPath, filename)
	case ReleaseFile, CloseFile:
		var (
			irp        uint64
			fileObject uint64
			fileKey    uint64
			tid        uint32
		)
		if evt.Version() >= 2 {
			irp = evt.ReadUint64(0)
		}
		if evt.Version() >= 3 {
			fileObject = evt.ReadUint64(8)
			fileKey = evt.ReadUint64(16)
			tid = evt.ReadUint32(24)
		}
		e.AppendParam(params.FileIrpPtr, params.Address, irp)
		e.AppendParam(params.FileObject, params.Address, fileObject)
		e.AppendParam(params.FileKey, params.Address, fileKey)
		e.AppendParam(params.ThreadID, params.TID, tid)
	case DeleteFile, RenameFile, SetFileInformation:
		var (
			irp        uint64
			fileObject uint64
			fileKey    uint64
			tid        uint32
			extraInfo  uint64
			infoClass  uint32
		)
		if evt.Version() >= 2 {
			irp = evt.ReadUint64(0)
		}
		if evt.Version() >= 3 {
			fileObject = evt.ReadUint64(8)
			fileKey = evt.ReadUint64(16)
			extraInfo = evt.ReadUint64(24)
			tid = evt.ReadUint32(32)
			infoClass = evt.ReadUint32(36)
		} else {
			tid = evt.ReadUint32(8)
			fileObject = evt.ReadUint64(12)
			fileKey = evt.ReadUint64(18)
			extraInfo = evt.ReadUint64(28)
		}
		e.AppendParam(params.FileIrpPtr, params.Address, irp)
		e.AppendParam(params.FileObject, params.Address, fileObject)
		e.AppendParam(params.FileKey, params.Address, fileKey)
		e.AppendParam(params.ThreadID, params.TID, tid)
		e.AppendParam(params.FileExtraInfo, params.Uint64, extraInfo)
		e.AppendParam(params.FileInfoClass, params.Enum, infoClass, WithEnum(fs.FileInfoClasses))
	case ReadFile, WriteFile:
		var (
			irp        uint64
			offset     uint64
			fileObject uint64
			fileKey    uint64
			tid        uint32
			size       uint32
		)
		if evt.Version() >= 2 {
			offset = evt.ReadUint64(0)
			irp = evt.ReadUint64(8)
		}
		if evt.Version() >= 3 {
			fileObject = evt.ReadUint64(16)
			fileKey = evt.ReadUint64(24)
			tid = evt.ReadUint32(32)
			size = evt.ReadUint32(34)
		} else {
			fileObject = evt.ReadUint64(20)
			fileKey = evt.ReadUint64(28)
			tid = evt.ReadUint32(16)
		}
		e.AppendParam(params.FileIrpPtr, params.Address, irp)
		e.AppendParam(params.FileObject, params.Address, fileObject)
		e.AppendParam(params.FileKey, params.Address, fileKey)
		e.AppendParam(params.ThreadID, params.TID, tid)
		e.AppendParam(params.FileOffset, params.Uint64, offset)
		e.AppendParam(params.FileIoSize, params.Uint32, size)
	case EnumDirectory:
		var (
			irp        uint64
			fileObject uint64
			fileKey    uint64
			tid        uint32
			infoClass  uint32
			filename   string
		)
		if evt.Version() >= 2 {
			irp = evt.ReadUint64(0)
		}
		if evt.Version() >= 3 {
			fileObject = evt.ReadUint64(8)
			fileKey = evt.ReadUint64(16)
			tid = evt.ReadUint32(24)
			infoClass = evt.ReadUint32(32)
			filename = evt.ConsumeUTF16String(38)
		} else {
			tid = evt.ReadUint32(8)
			fileObject = evt.ReadUint64(12)
			fileKey = evt.ReadUint64(20)
		}
		e.AppendParam(params.FileIrpPtr, params.Address, irp)
		e.AppendParam(params.FileObject, params.Address, fileObject)
		e.AppendParam(params.ThreadID, params.TID, tid)
		e.AppendParam(params.FileKey, params.Address, fileKey)
		e.AppendParam(params.FilePath, params.UnicodeString, filename)
		e.AppendParam(params.FileInfoClass, params.Enum, infoClass, WithEnum(fs.FileInfoClasses))
	case MapViewFile, UnmapViewFile, MapFileRundown:
		var (
			viewBase  uint64
			fileKey   uint64
			extraInfo uint64
			viewSize  uint64
			pid       uint32
			offset    uint64
		)
		viewBase = evt.ReadUint64(0)
		fileKey = evt.ReadUint64(8)
		extraInfo = evt.ReadUint64(16)
		viewSize = evt.ReadUint64(24)
		if evt.Version() >= 3 {
			offset = evt.ReadUint64(32)
		}
		if evt.Version() >= 3 {
			pid = evt.ReadUint32(40)
		} else {
			pid = evt.ReadUint32(32)
		}
		protect := uint32(extraInfo >> 32)
		section := uint32(extraInfo >> 52)
		e.AppendParam(params.FileViewBase, params.Address, viewBase)
		e.AppendParam(params.FileKey, params.Address, fileKey)
		e.AppendParam(params.FileViewSize, params.Uint64, viewSize)
		e.AppendParam(params.FileOffset, params.Uint64, offset)
		e.AppendParam(params.ProcessID, params.PID, pid)
		e.AppendParam(params.MemProtect, params.Flags, protect, WithFlags(ViewProtectionFlags))
		e.AppendParam(params.FileViewSectionType, params.Enum, section, WithEnum(ViewSectionTypes))
	case SendTCPv4,
		SendUDPv4,
		RecvTCPv4,
		RecvUDPv4,
		DisconnectTCPv4,
		RetransmitTCPv4,
		ReconnectTCPv4,
		ConnectTCPv4,
		AcceptTCPv4:
		var (
			pid   uint32
			size  uint32
			dip   uint32
			sip   uint32
			dport uint16
			sport uint16
		)
		if evt.Version() >= 1 {
			pid = evt.ReadUint32(0)
			size = evt.ReadUint32(4)
			dip = evt.ReadUint32(8)
			sip = evt.ReadUint32(12)
			dport = evt.ReadUint16(16)
			sport = evt.ReadUint16(18)
		} else {
			dip = evt.ReadUint32(0)
			sip = evt.ReadUint32(4)
			dport = evt.ReadUint16(8)
			sport = evt.ReadUint16(10)
			size = evt.ReadUint32(12)
			pid = evt.ReadUint32(16)
		}
		e.AppendParam(params.ProcessID, params.PID, pid)
		e.AppendParam(params.NetSize, params.Uint32, size)
		e.AppendParam(params.NetDIP, params.IPv4, dip)
		e.AppendParam(params.NetSIP, params.IPv4, sip)
		e.AppendParam(params.NetDport, params.Port, dport)
		e.AppendParam(params.NetSport, params.Port, sport)
	case SendTCPv6,
		SendUDPv6,
		RecvTCPv6,
		RecvUDPv6,
		DisconnectTCPv6,
		RetransmitTCPv6,
		ReconnectTCPv6,
		ConnectTCPv6,
		AcceptTCPv6:
		var (
			pid   uint32
			size  uint32
			dip   []byte
			sip   []byte
			dport uint16
			sport uint16
		)
		if evt.Version() >= 2 {
			pid = evt.ReadUint32(0)
			size = evt.ReadUint32(4)
			dip = evt.ReadBytes(8, 16)
			sip = evt.ReadBytes(24, 16)
			dport = evt.ReadUint16(40)
			sport = evt.ReadUint16(42)
		}
		e.AppendParam(params.ProcessID, params.PID, pid)
		e.AppendParam(params.NetSize, params.Uint32, size)
		e.AppendParam(params.NetDIP, params.IPv6, dip)
		e.AppendParam(params.NetSIP, params.IPv6, sip)
		e.AppendParam(params.NetDport, params.Port, dport)
		e.AppendParam(params.NetSport, params.Port, sport)
	case VirtualAlloc, VirtualFree:
		var (
			baseAddress uint64
			regionSize  uint64
			pid         uint32
			flags       uint32
		)
		if evt.Version() >= 1 {
			baseAddress = evt.ReadUint64(0)
			regionSize = evt.ReadUint64(8)
			pid = evt.ReadUint32(16)
			flags = evt.ReadUint32(20)
		}
		e.AppendParam(params.MemBaseAddress, params.Address, baseAddress)
		e.AppendParam(params.MemRegionSize, params.Uint64, regionSize)
		e.AppendParam(params.ProcessID, params.PID, pid)
		e.AppendParam(params.MemAllocType, params.Flags, flags, WithFlags(MemAllocationFlags))
	case QueryDNS, ReplyDNS:
		var (
			name string
			rr   uint32
			opts uint64
		)
		var offset uint16
		name, offset = evt.ReadUTF16String(0)
		rr = evt.ReadUint32(offset)
		opts = evt.ReadUint64(offset + 4)
		e.AppendParam(params.DNSName, params.UnicodeString, name)
		e.AppendParam(params.DNSRR, params.Enum, rr, WithEnum(DNSRecordTypes))
		e.AppendParam(params.DNSOpts, params.Flags64, opts, WithFlags(DNSOptsFlags))
		if e.Type == ReplyDNS {
			rcode := evt.ReadUint32(offset + 12)
			answers := evt.ConsumeUTF16String(offset + 16)
			e.AppendParam(params.DNSRcode, params.Enum, rcode, WithEnum(DNSResponseCodes))
			e.AppendParam(params.DNSAnswers, params.Slice, strings.Split(sanitizeDNSAnswers(answers), ";"))
		}
	case StackWalk:
		e.AppendParam(params.ProcessID, params.PID, evt.ReadUint32(8))
		e.AppendParam(params.ThreadID, params.TID, evt.ReadUint32(12))
		var n uint16
		var offset uint16 = 16
		frames := (evt.BufferLen - offset) / 8
		callstack := make([]va.Address, frames)
		for n < frames {
			callstack[n] = va.Address(evt.ReadUint64(offset))
			offset += 8
			n++
		}
		e.AppendParam(params.Callstack, params.Slice, callstack)
	case CreateSymbolicLinkObject:
		source, offset := evt.ReadUTF16String(0)
		target, offset := evt.ReadUTF16String(offset)
		desiredAccess := evt.ReadUint32(offset)
		status := evt.ReadUint32(offset + 4)
		e.AppendParam(params.LinkSource, params.UnicodeString, source)
		e.AppendParam(params.LinkTarget, params.UnicodeString, target)
		e.AppendParam(params.DesiredAccess, params.Flags, desiredAccess, WithFlags(AccessMaskFlags))
		e.AppendParam(params.NTStatus, params.Status, status)
		if evt.HasStackTrace() {
			e.AppendParam(params.Callstack, params.Slice, evt.Callstack())
		}
	case SubmitThreadpoolWork, SubmitThreadpoolCallback:
		poolID := evt.ReadUint64(0)
		taskID := evt.ReadUint64(8)
		callback := evt.ReadUint64(16)
		ctx := evt.ReadUint64(24)
		tag := evt.ReadUint64(32)
		e.AppendParam(params.ThreadpoolPoolID, params.Address, poolID)
		e.AppendParam(params.ThreadpoolTaskID, params.Address, taskID)
		e.AppendParam(params.ThreadpoolCallback, params.Address, callback)
		e.AppendParam(params.ThreadpoolContext, params.Address, ctx)
		e.AppendParam(params.ThreadpoolSubprocessTag, params.Address, tag)
	case SetThreadpoolTimer:
		duetime := evt.ReadUint64(0)
		subqueue := evt.ReadUint64(8)
		timer := evt.ReadUint64(16)
		period := evt.ReadUint32(24)
		window := evt.ReadUint32(28)
		absolute := evt.ReadUint32(32)
		e.AppendParam(params.ThreadpoolTimerDuetime, params.Uint64, duetime)
		e.AppendParam(params.ThreadpoolTimerSubqueue, params.Address, subqueue)
		e.AppendParam(params.ThreadpoolTimer, params.Address, timer)
		e.AppendParam(params.ThreadpoolTimerPeriod, params.Uint32, period)
		e.AppendParam(params.ThreadpoolTimerWindow, params.Uint32, window)
		e.AppendParam(params.ThreadpoolTimerAbsolute, params.Bool, absolute > 0)
	}
}

// sanitizeDNSAnswers removes the "type" string from DNS answers.
func sanitizeDNSAnswers(answers string) string {
	return strings.ReplaceAll(answers, "type: 5 ", "")
}
