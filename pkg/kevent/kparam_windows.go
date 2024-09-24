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

package kevent

import (
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/fs"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
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

// NewKparam creates a new event parameter. Since the parameter type is already categorized,
// we can coerce the value to the appropriate representation (e.g. hex, IP address)
func NewKparam(name string, typ kparams.Type, value kparams.Value, options ...ParamOption) *Kparam {
	var opts paramOpts
	for _, opt := range options {
		opt(&opts)
	}
	var v kparams.Value
	switch typ {
	case kparams.IPv4:
		v = ip.ToIPv4(value.(uint32))
	case kparams.IPv6:
		v = ip.ToIPv6(value.([]byte))
	case kparams.Port:
		v = windows.Ntohs(value.(uint16))
	default:
		v = value
	}
	return &Kparam{Name: name, Type: typ, Value: v, Flags: opts.flags, Enum: opts.enum}
}

var devMapper = fs.NewDevMapper()

// String returns the string representation of the parameter value.
func (k Kparam) String() string {
	if k.Value == nil {
		return ""
	}
	switch k.Type {
	case kparams.UnicodeString, kparams.AnsiString, kparams.FilePath:
		return k.Value.(string)
	case kparams.SID, kparams.WbemSID:
		sid, err := getSID(&k)
		if err != nil {
			return ""
		}
		return sid.String()
	case kparams.FileDosPath:
		return devMapper.Convert(k.Value.(string))
	case kparams.Key:
		rootKey, keyName := key.Format(k.Value.(string))
		if keyName != "" && rootKey != key.Invalid {
			return rootKey.String() + "\\" + keyName
		}
		if rootKey != key.Invalid {
			return rootKey.String()
		}
		unknownKeysCount.Add(1)
		return keyName
	case kparams.HandleType:
		return htypes.ConvertTypeIDToName(k.Value.(uint16))
	case kparams.Status:
		v, ok := k.Value.(uint32)
		if !ok {
			return ""
		}
		return ntstatus.FormatMessage(v)
	case kparams.Address:
		v, ok := k.Value.(uint64)
		if !ok {
			return ""
		}
		return va.Address(v).String()
	case kparams.Int8:
		return strconv.Itoa(int(k.Value.(int8)))
	case kparams.Uint8:
		return strconv.Itoa(int(k.Value.(uint8)))
	case kparams.Int16:
		return strconv.Itoa(int(k.Value.(int16)))
	case kparams.Uint16, kparams.Port:
		return strconv.Itoa(int(k.Value.(uint16)))
	case kparams.Uint32, kparams.PID, kparams.TID:
		return strconv.Itoa(int(k.Value.(uint32)))
	case kparams.Int32:
		return strconv.Itoa(int(k.Value.(int32)))
	case kparams.Uint64:
		return strconv.FormatUint(k.Value.(uint64), 10)
	case kparams.Int64:
		return strconv.Itoa(int(k.Value.(int64)))
	case kparams.IPv4, kparams.IPv6:
		return k.Value.(net.IP).String()
	case kparams.Bool:
		return strconv.FormatBool(k.Value.(bool))
	case kparams.Float:
		return strconv.FormatFloat(float64(k.Value.(float32)), 'f', 6, 32)
	case kparams.Double:
		return strconv.FormatFloat(k.Value.(float64), 'f', 6, 64)
	case kparams.Time:
		return k.Value.(time.Time).String()
	case kparams.Enum:
		if k.Enum == nil {
			return ""
		}
		e := k.Value
		v, ok := e.(uint32)
		if !ok {
			return ""
		}
		return k.Enum[v]
	case kparams.Flags, kparams.Flags64:
		if k.Flags == nil {
			return ""
		}
		f := k.Value
		switch v := f.(type) {
		case uint32:
			return k.Flags.String(uint64(v))
		case uint64:
			return k.Flags.String(v)
		default:
			return ""
		}
	case kparams.Slice:
		switch slice := k.Value.(type) {
		case []string:
			return strings.Join(slice, ",")
		default:
			return fmt.Sprintf("%v", slice)
		}
	case kparams.Binary:
		return string(k.Value.([]byte))
	}
	return fmt.Sprintf("%v", k.Value)
}

// GetSID returns the raw SID (Security Identifier) parameter as
// typed representation on which various operations can be performed,
// such as converting the SID to string or resolving username/domain.
func (kpars Kparams) GetSID() (*windows.SID, error) {
	kpar, err := kpars.findParam(kparams.UserSID)
	if err != nil {
		return nil, err
	}
	return getSID(kpar)
}

func getSID(kpar *Kparam) (*windows.SID, error) {
	sid, ok := kpar.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("unable to type cast %q parameter to []byte value", kparams.UserSID)
	}
	b := uintptr(unsafe.Pointer(&sid[0]))
	if kpar.Type == kparams.WbemSID {
		// a WBEM SID is actually a TOKEN_USER structure followed
		// by the SID, so we have to double the pointer size
		b += uintptr(8 * 2)
	}
	return (*windows.SID)(unsafe.Pointer(b)), nil
}

// MustGetSID returns the SID (Security Identifier) event parameter
// or panics if an error occurs.
func (kpars Kparams) MustGetSID() *windows.SID {
	sid, err := kpars.GetSID()
	if err != nil {
		panic(err)
	}
	return sid
}

// produceParams parses the event binary layout to extract
// the parameters. Each event is annotated with the schema
// version number which helps us determine when the event
// schema changes in order to parse new fields.
func (e *Kevent) produceParams(evt *etw.EventRecord) {
	switch e.Type {
	case ktypes.ProcessRundown,
		ktypes.CreateProcess,
		ktypes.TerminateProcess:
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
		sid, soffset = evt.ReadSID(offset)
		name, noffset = evt.ReadAnsiString(soffset)
		cmdline, _ = evt.ReadUTF16String(soffset + noffset)
		e.AppendParam(kparams.ProcessObject, kparams.Address, kproc)
		e.AppendParam(kparams.ProcessID, kparams.PID, pid)
		e.AppendParam(kparams.ProcessParentID, kparams.PID, ppid)
		e.AppendParam(kparams.ProcessRealParentID, kparams.PID, evt.Header.ProcessID)
		e.AppendParam(kparams.SessionID, kparams.Uint32, sessionID)
		e.AppendParam(kparams.ExitStatus, kparams.Status, exitStatus)
		e.AppendParam(kparams.DTB, kparams.Address, dtb)
		e.AppendParam(kparams.ProcessFlags, kparams.Flags, flags, WithFlags(PsCreationFlags))
		e.AppendParam(kparams.UserSID, kparams.WbemSID, sid)
		e.AppendParam(kparams.ProcessName, kparams.AnsiString, name)
		e.AppendParam(kparams.Cmdline, kparams.UnicodeString, cmdline)
	case ktypes.OpenProcess:
		processID := evt.ReadUint32(0)
		desiredAccess := evt.ReadUint32(4)
		status := evt.ReadUint32(8)
		e.AppendParam(kparams.ProcessID, kparams.PID, processID)
		e.AppendParam(kparams.DesiredAccess, kparams.Flags, desiredAccess, WithFlags(PsAccessRightFlags))
		e.AppendParam(kparams.NTStatus, kparams.Status, status)
	case ktypes.CreateThread,
		ktypes.TerminateThread,
		ktypes.ThreadRundown:
		var (
			pid            uint32
			tid            uint32
			kstack, klimit uint64
			ustack, ulimit uint64
			startAddress   uint64
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
		}
		if evt.Version() >= 3 {
			basePrio = evt.ReadByte(69)
			pagePrio = evt.ReadByte(70)
			ioPrio = evt.ReadByte(71)
		}
		e.AppendParam(kparams.ProcessID, kparams.PID, pid)
		e.AppendParam(kparams.ThreadID, kparams.TID, tid)
		e.AppendParam(kparams.KstackBase, kparams.Address, kstack)
		e.AppendParam(kparams.KstackLimit, kparams.Address, klimit)
		e.AppendParam(kparams.UstackBase, kparams.Address, ustack)
		e.AppendParam(kparams.UstackLimit, kparams.Address, ulimit)
		e.AppendParam(kparams.StartAddress, kparams.Address, startAddress)
		e.AppendParam(kparams.BasePrio, kparams.Uint8, basePrio)
		e.AppendParam(kparams.PagePrio, kparams.Uint8, pagePrio)
		e.AppendParam(kparams.IOPrio, kparams.Uint8, ioPrio)
	case ktypes.OpenThread:
		processID := evt.ReadUint32(0)
		threadID := evt.ReadUint32(4)
		desiredAccess := evt.ReadUint32(8)
		status := evt.ReadUint32(12)
		e.AppendParam(kparams.ProcessID, kparams.PID, processID)
		e.AppendParam(kparams.ThreadID, kparams.TID, threadID)
		e.AppendParam(kparams.DesiredAccess, kparams.Flags, desiredAccess, WithFlags(ThreadAccessRightFlags))
		e.AppendParam(kparams.NTStatus, kparams.Status, status)
	case ktypes.SetThreadContext:
		status := evt.ReadUint32(0)
		e.AppendParam(kparams.NTStatus, kparams.Status, status)
		if evt.HasStackTrace() {
			e.AppendParam(kparams.Callstack, kparams.Slice, evt.Callstack())
		}
	case ktypes.CreateHandle, ktypes.CloseHandle:
		object := evt.ReadUint64(0)
		handleID := evt.ReadUint32(8)
		typeID := evt.ReadUint16(12)
		var handleName string
		if evt.BufferLen >= 16 {
			handleName = evt.ConsumeUTF16String(14)
		}
		e.AppendParam(kparams.HandleObject, kparams.Address, object)
		e.AppendParam(kparams.HandleID, kparams.Uint32, handleID)
		e.AppendParam(kparams.HandleObjectTypeID, kparams.HandleType, typeID)
		e.AppendParam(kparams.HandleObjectName, kparams.UnicodeString, handleName)
	case ktypes.DuplicateHandle:
		object := evt.ReadUint64(0)
		srcHandleID := evt.ReadUint32(8)
		dstHandleID := evt.ReadUint32(12)
		targetPID := evt.ReadUint32(16)
		typeID := evt.ReadUint16(20)
		sourcePID := evt.ReadUint32(22)
		e.AppendParam(kparams.HandleObject, kparams.Address, object)
		e.AppendParam(kparams.HandleID, kparams.Uint32, dstHandleID)
		e.AppendParam(kparams.HandleSourceID, kparams.Uint32, srcHandleID)
		e.AppendParam(kparams.HandleObjectTypeID, kparams.HandleType, typeID)
		e.AppendParam(kparams.ProcessID, kparams.PID, sourcePID)
		e.AppendParam(kparams.TargetProcessID, kparams.PID, targetPID)
	case ktypes.LoadImage,
		ktypes.UnloadImage,
		ktypes.ImageRundown:
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
		e.AppendParam(kparams.ProcessID, kparams.PID, pid)
		e.AppendParam(kparams.ImageCheckSum, kparams.Uint32, checksum)
		e.AppendParam(kparams.ImageDefaultBase, kparams.Address, defaultBase)
		e.AppendParam(kparams.ImageBase, kparams.Address, imageBase)
		e.AppendParam(kparams.ImageSize, kparams.Uint64, imageSize)
		e.AppendParam(kparams.ImageFilename, kparams.FileDosPath, filename)
		e.AppendParam(kparams.ImageSignatureLevel, kparams.Enum, uint32(sigLevel), WithEnum(signature.Levels))
		e.AppendParam(kparams.ImageSignatureType, kparams.Enum, uint32(sigType), WithEnum(signature.Types))
	case ktypes.RegOpenKey, ktypes.RegCloseKey,
		ktypes.RegCreateKCB, ktypes.RegDeleteKCB,
		ktypes.RegKCBRundown, ktypes.RegCreateKey,
		ktypes.RegDeleteKey, ktypes.RegDeleteValue,
		ktypes.RegQueryKey, ktypes.RegQueryValue,
		ktypes.RegSetValue:
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
		e.AppendParam(kparams.RegKeyHandle, kparams.Address, keyHandle)
		e.AppendParam(kparams.RegKeyName, kparams.Key, keyName)
		e.AppendParam(kparams.NTStatus, kparams.Status, status)
	case ktypes.CreateFile:
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
		e.AppendParam(kparams.FileIrpPtr, kparams.Address, irp)
		e.AppendParam(kparams.FileObject, kparams.Address, fileObject)
		e.AppendParam(kparams.ThreadID, kparams.TID, tid)
		e.AppendParam(kparams.FileShareMask, kparams.Flags, shareAccess, WithFlags(FileShareModeFlags))
		e.AppendParam(kparams.FileAttributes, kparams.Flags, fileAttributes, WithFlags(FileAttributeFlags))
		e.AppendParam(kparams.FileCreateOptions, kparams.Flags, createOptions, WithFlags(FileCreateOptionsFlags))
		e.AppendParam(kparams.FileName, kparams.FileDosPath, filename)
	case ktypes.FileOpEnd:
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
		e.AppendParam(kparams.FileIrpPtr, kparams.Address, irp)
		e.AppendParam(kparams.FileExtraInfo, kparams.Address, extraInfo)
		e.AppendParam(kparams.NTStatus, kparams.Status, status)
	case ktypes.FileRundown:
		var (
			fileObject uint64
			filename   string
		)
		if evt.Version() >= 2 {
			fileObject = evt.ReadUint64(0)
			filename = evt.ConsumeUTF16String(8)
		}
		e.AppendParam(kparams.FileObject, kparams.Address, fileObject)
		e.AppendParam(kparams.FileName, kparams.FileDosPath, filename)
	case ktypes.ReleaseFile, ktypes.CloseFile:
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
		e.AppendParam(kparams.FileIrpPtr, kparams.Address, irp)
		e.AppendParam(kparams.FileObject, kparams.Address, fileObject)
		e.AppendParam(kparams.FileKey, kparams.Address, fileKey)
		e.AppendParam(kparams.ThreadID, kparams.TID, tid)
	case ktypes.DeleteFile,
		ktypes.RenameFile,
		ktypes.SetFileInformation:
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
		e.AppendParam(kparams.FileIrpPtr, kparams.Address, irp)
		e.AppendParam(kparams.FileObject, kparams.Address, fileObject)
		e.AppendParam(kparams.FileKey, kparams.Address, fileKey)
		e.AppendParam(kparams.ThreadID, kparams.TID, tid)
		e.AppendParam(kparams.FileExtraInfo, kparams.Uint64, extraInfo)
		e.AppendParam(kparams.FileInfoClass, kparams.Enum, infoClass, WithEnum(fs.FileInfoClasses))
	case ktypes.ReadFile, ktypes.WriteFile:
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
		e.AppendParam(kparams.FileIrpPtr, kparams.Address, irp)
		e.AppendParam(kparams.FileObject, kparams.Address, fileObject)
		e.AppendParam(kparams.FileKey, kparams.Address, fileKey)
		e.AppendParam(kparams.ThreadID, kparams.TID, tid)
		e.AppendParam(kparams.FileOffset, kparams.Uint64, offset)
		e.AppendParam(kparams.FileIoSize, kparams.Uint32, size)
	case ktypes.EnumDirectory:
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
		e.AppendParam(kparams.FileIrpPtr, kparams.Address, irp)
		e.AppendParam(kparams.FileObject, kparams.Address, fileObject)
		e.AppendParam(kparams.ThreadID, kparams.TID, tid)
		e.AppendParam(kparams.FileKey, kparams.Address, fileKey)
		e.AppendParam(kparams.FileName, kparams.UnicodeString, filename)
		e.AppendParam(kparams.FileInfoClass, kparams.Enum, infoClass, WithEnum(fs.FileInfoClasses))
	case ktypes.MapViewFile, ktypes.UnmapViewFile, ktypes.MapFileRundown:
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
		e.AppendParam(kparams.FileViewBase, kparams.Address, viewBase)
		e.AppendParam(kparams.FileKey, kparams.Address, fileKey)
		e.AppendParam(kparams.FileViewSize, kparams.Uint64, viewSize)
		e.AppendParam(kparams.FileOffset, kparams.Uint64, offset)
		e.AppendParam(kparams.ProcessID, kparams.PID, pid)
		e.AppendParam(kparams.MemProtect, kparams.Flags, protect, WithFlags(ViewProtectionFlags))
		e.AppendParam(kparams.FileViewSectionType, kparams.Enum, section, WithEnum(ViewSectionTypes))
	case ktypes.SendTCPv4,
		ktypes.SendUDPv4,
		ktypes.RecvTCPv4,
		ktypes.RecvUDPv4,
		ktypes.DisconnectTCPv4,
		ktypes.RetransmitTCPv4,
		ktypes.ReconnectTCPv4,
		ktypes.ConnectTCPv4,
		ktypes.AcceptTCPv4:
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
		e.AppendParam(kparams.ProcessID, kparams.PID, pid)
		e.AppendParam(kparams.NetSize, kparams.Uint32, size)
		e.AppendParam(kparams.NetDIP, kparams.IPv4, dip)
		e.AppendParam(kparams.NetSIP, kparams.IPv4, sip)
		e.AppendParam(kparams.NetDport, kparams.Port, dport)
		e.AppendParam(kparams.NetSport, kparams.Port, sport)
	case ktypes.SendTCPv6,
		ktypes.SendUDPv6,
		ktypes.RecvTCPv6,
		ktypes.RecvUDPv6,
		ktypes.DisconnectTCPv6,
		ktypes.RetransmitTCPv6,
		ktypes.ReconnectTCPv6,
		ktypes.ConnectTCPv6,
		ktypes.AcceptTCPv6:
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
		e.AppendParam(kparams.ProcessID, kparams.PID, pid)
		e.AppendParam(kparams.NetSize, kparams.Uint32, size)
		e.AppendParam(kparams.NetDIP, kparams.IPv6, dip)
		e.AppendParam(kparams.NetSIP, kparams.IPv6, sip)
		e.AppendParam(kparams.NetDport, kparams.Port, dport)
		e.AppendParam(kparams.NetSport, kparams.Port, sport)
	case ktypes.VirtualAlloc, ktypes.VirtualFree:
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
		e.AppendParam(kparams.MemBaseAddress, kparams.Address, baseAddress)
		e.AppendParam(kparams.MemRegionSize, kparams.Uint64, regionSize)
		e.AppendParam(kparams.ProcessID, kparams.PID, pid)
		e.AppendParam(kparams.MemAllocType, kparams.Flags, flags, WithFlags(MemAllocationFlags))
	case ktypes.QueryDNS, ktypes.ReplyDNS:
		var (
			name string
			rr   uint32
			opts uint64
		)
		var offset uint16
		name, offset = evt.ReadUTF16String(0)
		rr = evt.ReadUint32(offset)
		opts = evt.ReadUint64(offset + 4)
		e.AppendParam(kparams.DNSName, kparams.UnicodeString, name)
		e.AppendParam(kparams.DNSRR, kparams.Enum, rr, WithEnum(DNSRecordTypes))
		e.AppendParam(kparams.DNSOpts, kparams.Flags64, opts, WithFlags(DNSOptsFlags))
		if e.Type == ktypes.ReplyDNS {
			rcode := evt.ReadUint32(offset + 12)
			answers := evt.ConsumeUTF16String(offset + 16)
			e.AppendParam(kparams.DNSRcode, kparams.Enum, rcode, WithEnum(DNSResponseCodes))
			e.AppendParam(kparams.DNSAnswers, kparams.Slice, strings.Split(sanitizeDNSAnswers(answers), ";"))
		}
	case ktypes.StackWalk:
		e.AppendParam(kparams.ProcessID, kparams.PID, evt.ReadUint32(8))
		e.AppendParam(kparams.ThreadID, kparams.TID, evt.ReadUint32(12))
		var n uint16
		var offset uint16 = 16
		frames := (evt.BufferLen - offset) / 8
		callstack := make([]va.Address, frames)
		for n < frames {
			callstack[n] = va.Address(evt.ReadUint64(offset))
			offset += 8
			n++
		}
		e.AppendParam(kparams.Callstack, kparams.Slice, callstack)
	}
}

// sanitizeDNSAnswers removes the "type" string from DNS answers.
func sanitizeDNSAnswers(answers string) string {
	return strings.ReplaceAll(answers, "type: 5 ", "")
}
