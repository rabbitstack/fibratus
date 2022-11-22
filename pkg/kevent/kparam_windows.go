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
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
	"github.com/rabbitstack/fibratus/pkg/syscall/registry"
	"github.com/rabbitstack/fibratus/pkg/syscall/security"
	"github.com/rabbitstack/fibratus/pkg/util/ip"
	"github.com/rabbitstack/fibratus/pkg/util/key"
	"github.com/rabbitstack/fibratus/pkg/util/status"
	"golang.org/x/sys/windows"
	"net"
	"strconv"
	"strings"
	"time"
)

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
	case kparams.HexInt8, kparams.HexInt16, kparams.HexInt32, kparams.HexInt64:
		v = kparams.NewHex(value)
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
	case kparams.SID:
		account, domain := security.LookupAccount(k.Value.([]byte), false)
		if account != "" || domain != "" {
			return joinSID(account, domain)
		}
		return ""
	case kparams.WbemSID:
		account, domain := security.LookupAccount(k.Value.([]byte), true)
		if account != "" || domain != "" {
			return joinSID(account, domain)
		}
		return ""
	case kparams.FileDosPath:
		return devMapper.Convert(k.Value.(string))
	case kparams.Key:
		rootKey, keyName := key.Format(k.Value.(string))
		if keyName != "" && rootKey != registry.InvalidKey {
			return rootKey.String() + "\\" + keyName
		}
		if rootKey == registry.InvalidKey {
			unknownKeysCount.Add(1)
			return keyName
		}
	case kparams.Status:
		v, ok := k.Value.(uint32)
		if !ok {
			return ""
		}
		return status.FormatMessage(v)
	case kparams.HexInt32, kparams.HexInt64, kparams.HexInt16, kparams.HexInt8:
		return string(k.Value.(kparams.Hex))
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
		v, ok := k.Value.(uint32)
		if !ok {
			return ""
		}
		return k.Enum[v]
	case kparams.Flags:
		v, ok := k.Value.(uint32)
		if !ok {
			return ""
		}
		if k.Flags != nil {
			return k.Flags.String(v)
		}
		return ""
	case kparams.Slice:
		switch slice := k.Value.(type) {
		case []string:
			return strings.Join(slice, ",")
		default:
			return fmt.Sprintf("%v", slice)
		}
	}
	return fmt.Sprintf("%v", k.Value)
}

// produceParams parses the event binary layout to extract the parameters. Each event is annotated with the
// schema version number which helps us determine when the event schema changes in order to parse new fields.
func (kevt *Kevent) produceParams(e *etw.EventRecord) {
	switch kevt.Type {
	case ktypes.ProcessRundown,
		ktypes.CreateProcess,
		ktypes.TerminateProcess:
		var (
			kproc      uint64
			pid, ppid  uint32
			sessionID  uint32
			exitStatus uint32
			dtb        uint64
			sid        []byte
			name       string
			cmdline    string
		)
		var offset uint16
		var soffset uint16
		var noffset uint16
		if e.Version() >= 1 {
			pid = e.ReadUint32(8)
			ppid = e.ReadUint32(12)
			sessionID = e.ReadUint32(16)
			exitStatus = e.ReadUint32(20)
		}
		if e.Version() >= 2 {
			kproc = e.ReadUint64(0)
		}
		if e.Version() >= 3 {
			dtb = e.ReadUint64(24)
		}
		switch {
		case e.Version() >= 4:
			offset = 36
		case e.Version() >= 3:
			offset = 32
		default:
			offset = 24
		}
		sid, soffset = e.ReadSID(offset)
		name, noffset = e.ReadAnsiString(soffset)
		cmdline, _ = e.ReadUTF16String(soffset + noffset)
		kevt.AppendParam(kparams.ProcessObject, kparams.HexInt64, kproc)
		kevt.AppendParam(kparams.ProcessID, kparams.PID, pid)
		kevt.AppendParam(kparams.ProcessParentID, kparams.PID, ppid)
		kevt.AppendParam(kparams.ProcessRealParentID, kparams.PID, e.Header.ProcessID)
		kevt.AppendParam(kparams.SessionID, kparams.Uint32, sessionID)
		kevt.AppendParam(kparams.ExitStatus, kparams.Status, exitStatus)
		kevt.AppendParam(kparams.DTB, kparams.HexInt64, dtb)
		kevt.AppendParam(kparams.UserSID, kparams.WbemSID, sid)
		kevt.AppendParam(kparams.ProcessName, kparams.AnsiString, name)
		kevt.AppendParam(kparams.Cmdline, kparams.UnicodeString, cmdline)
	case ktypes.OpenProcess:
		processID := e.ReadUint32(0)
		desiredAccess := e.ReadUint32(4)
		status := e.ReadUint32(8)
		kevt.AppendParam(kparams.ProcessID, kparams.PID, processID)
		kevt.AppendParam(kparams.DesiredAccess, kparams.Flags, desiredAccess, WithFlags(PsAccessRightFlags))
		kevt.AppendParam(kparams.NTStatus, kparams.Status, status)
	case ktypes.CreateThread,
		ktypes.TerminateThread,
		ktypes.ThreadRundown:
		var (
			pid            uint32
			tid            uint32
			kstack, klimit uint64
			ustack, ulimit uint64
			startAddr      uint64
			basePrio       uint8
			pagePrio       uint8
			ioPrio         uint8
		)
		if e.Version() >= 1 {
			pid = e.ReadUint32(0)
			tid = e.ReadUint32(4)
		} else {
			pid = e.ReadUint32(4)
			tid = e.ReadUint32(0)
		}
		if e.Version() >= 2 {
			kstack = e.ReadUint64(8)
			klimit = e.ReadUint64(16)
			ustack = e.ReadUint64(24)
			ulimit = e.ReadUint64(32)
			startAddr = e.ReadUint64(48)
		}
		if e.Version() >= 3 {
			basePrio = e.ReadByte(69)
			pagePrio = e.ReadByte(70)
			ioPrio = e.ReadByte(71)
		}
		kevt.AppendParam(kparams.ProcessID, kparams.PID, pid)
		kevt.AppendParam(kparams.ThreadID, kparams.TID, tid)
		kevt.AppendParam(kparams.KstackBase, kparams.Address, kstack)
		kevt.AppendParam(kparams.KstackLimit, kparams.Address, klimit)
		kevt.AppendParam(kparams.UstackBase, kparams.Address, ustack)
		kevt.AppendParam(kparams.UstackLimit, kparams.Address, ulimit)
		kevt.AppendParam(kparams.StartAddr, kparams.Address, startAddr)
		kevt.AppendParam(kparams.BasePrio, kparams.Uint8, basePrio)
		kevt.AppendParam(kparams.PagePrio, kparams.Uint8, pagePrio)
		kevt.AppendParam(kparams.IOPrio, kparams.Uint8, ioPrio)
	case ktypes.OpenThread:
		processID := e.ReadUint32(0)
		threadID := e.ReadUint32(4)
		desiredAccess := e.ReadUint32(8)
		status := e.ReadUint32(12)
		kevt.AppendParam(kparams.ProcessID, kparams.PID, processID)
		kevt.AppendParam(kparams.ThreadID, kparams.TID, threadID)
		kevt.AppendParam(kparams.DesiredAccess, kparams.Flags, desiredAccess, WithFlags(ThreadAccessRightFlags))
		kevt.AppendParam(kparams.NTStatus, kparams.Status, status)
	case ktypes.CreateHandle, ktypes.CloseHandle:
		object := e.ReadUint64(0)
		handleID := e.ReadUint32(8)
		typeID := e.ReadUint16(12)
		var handleName string
		if e.BufferLen >= 16 {
			handleName = e.ConsumeUTF16String(14)
		}
		kevt.AppendParam(kparams.HandleObject, kparams.Uint64, object)
		kevt.AppendParam(kparams.HandleID, kparams.Uint32, handleID)
		kevt.AppendParam(kparams.HandleObjectTypeID, kparams.Uint16, typeID)
		kevt.AppendParam(kparams.HandleObjectName, kparams.UnicodeString, handleName)
	case ktypes.LoadImage,
		ktypes.UnloadImage,
		ktypes.ImageRundown:
		var (
			pid         uint32
			checksum    uint32
			defaultBase uint64
			filename    string
		)
		var offset uint16
		imageBase := e.ReadUint64(0)
		imageSize := e.ReadUint64(8)
		if e.Version() >= 1 {
			pid = e.ReadUint32(16)
		}
		if e.Version() >= 2 {
			checksum = e.ReadUint32(20)
			defaultBase = e.ReadUint64(30)
		}
		if e.Version() >= 3 {
			defaultBase = e.ReadUint64(32)
		}
		switch {
		case e.Version() >= 3:
			offset = 56
		case e.Version() >= 2:
			offset = 54
		case e.Version() >= 1:
			offset = 20
		default:
			offset = 16
		}
		filename, _ = e.ReadUTF16String(offset)
		kevt.AppendParam(kparams.ProcessID, kparams.Uint32, pid)
		kevt.AppendParam(kparams.ImageCheckSum, kparams.Uint32, checksum)
		kevt.AppendParam(kparams.ImageDefaultBase, kparams.Address, defaultBase)
		kevt.AppendParam(kparams.ImageBase, kparams.Address, imageBase)
		kevt.AppendParam(kparams.ImageSize, kparams.Uint32, uint32(imageSize))
		kevt.AppendParam(kparams.ImageFilename, kparams.FileDosPath, filename)
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
		if e.Version() >= 2 {
			status = e.ReadUint32(8)
			keyHandle = e.ReadUint64(16)
		} else {
			status = e.ReadUint32(0)
			keyHandle = e.ReadUint64(4)
		}
		if e.Version() >= 1 {
			keyName = e.ConsumeUTF16String(24)
		} else {
			keyName = e.ConsumeUTF16String(20)
		}
		kevt.AppendParam(kparams.RegKeyHandle, kparams.Uint64, keyHandle)
		kevt.AppendParam(kparams.RegKeyName, kparams.Key, keyName)
		kevt.AppendParam(kparams.NTStatus, kparams.Status, status)
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
		if e.Version() >= 2 {
			irp = e.ReadUint64(0)
			fileObject = e.ReadUint64(8)
			tid = e.ReadUint32(16)
			createOptions = e.ReadUint32(20)
			fileAttributes = e.ReadUint32(24)
			shareAccess = e.ReadUint32(28)
			filename = e.ConsumeUTF16String(32)
		} else {
			fileObject = e.ReadUint64(0)
			filename = e.ConsumeUTF16String(8)
		}
		kevt.AppendParam(kparams.FileIrpPtr, kparams.Uint64, irp)
		kevt.AppendParam(kparams.FileObject, kparams.Uint64, fileObject)
		kevt.AppendParam(kparams.ThreadID, kparams.TID, tid)
		kevt.AppendParam(kparams.FileCreateOptions, kparams.Flags, createOptions)
		kevt.AppendParam(kparams.FileAttributes, kparams.Flags, fileAttributes, WithFlags(FileAttributeFlags))
		kevt.AppendParam(kparams.FileShareMask, kparams.Flags, shareAccess)
		kevt.AppendParam(kparams.FileName, kparams.FileDosPath, filename)
	case ktypes.FileOpEnd:
		var (
			irp       uint64
			extraInfo uint64
			status    uint32
		)
		if e.Version() >= 2 {
			irp = e.ReadUint64(0)
			extraInfo = e.ReadUint64(8)
			status = e.ReadUint32(16)
		}
		kevt.AppendParam(kparams.FileIrpPtr, kparams.Uint64, irp)
		kevt.AppendParam(kparams.FileExtraInfo, kparams.Uint64, extraInfo)
		kevt.AppendParam(kparams.NTStatus, kparams.Status, status)
	case ktypes.FileRundown:
		var (
			fileObject uint64
			filename   string
		)
		if e.Version() >= 2 {
			fileObject = e.ReadUint64(0)
			filename = e.ConsumeUTF16String(8)
		}
		kevt.AppendParam(kparams.FileObject, kparams.Uint64, fileObject)
		kevt.AppendParam(kparams.FileName, kparams.FileDosPath, filename)
	case ktypes.ReleaseFile, ktypes.CloseFile:
		var (
			irp        uint64
			fileObject uint64
			fileKey    uint64
			tid        uint32
		)
		if e.Version() >= 2 {
			irp = e.ReadUint64(0)
		}
		if e.Version() >= 3 {
			fileObject = e.ReadUint64(8)
			fileKey = e.ReadUint64(16)
			tid = e.ReadUint32(24)
		}
		kevt.AppendParam(kparams.FileIrpPtr, kparams.Uint64, irp)
		kevt.AppendParam(kparams.FileObject, kparams.Uint64, fileObject)
		kevt.AppendParam(kparams.FileKey, kparams.Uint64, fileKey)
		kevt.AppendParam(kparams.ThreadID, kparams.TID, tid)
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
		if e.Version() >= 2 {
			irp = e.ReadUint64(0)
		}
		if e.Version() >= 3 {
			fileObject = e.ReadUint64(8)
			fileKey = e.ReadUint64(16)
			extraInfo = e.ReadUint64(24)
			tid = e.ReadUint32(32)
			infoClass = e.ReadUint32(36)
		} else {
			tid = e.ReadUint32(8)
			fileObject = e.ReadUint64(12)
			fileKey = e.ReadUint64(18)
			extraInfo = e.ReadUint64(28)
		}
		kevt.AppendParam(kparams.FileIrpPtr, kparams.Uint64, irp)
		kevt.AppendParam(kparams.FileObject, kparams.Uint64, fileObject)
		kevt.AppendParam(kparams.FileKey, kparams.Uint64, fileKey)
		kevt.AppendParam(kparams.ThreadID, kparams.TID, tid)
		kevt.AppendParam(kparams.FileExtraInfo, kparams.Uint64, extraInfo)
		kevt.AppendParam(kparams.FileInfoClass, kparams.Enum, infoClass, WithEnum(fs.FileInfoClasses))
	case ktypes.ReadFile, ktypes.WriteFile:
		var (
			irp        uint64
			offset     uint64
			fileObject uint64
			fileKey    uint64
			tid        uint32
			size       uint32
		)
		if e.Version() >= 2 {
			offset = e.ReadUint64(0)
			irp = e.ReadUint64(8)
		}
		if e.Version() >= 3 {
			fileObject = e.ReadUint64(16)
			fileKey = e.ReadUint64(24)
			tid = e.ReadUint32(32)
			size = e.ReadUint32(34)
		} else {
			fileObject = e.ReadUint64(20)
			fileKey = e.ReadUint64(28)
			tid = e.ReadUint32(16)
		}
		kevt.AppendParam(kparams.FileIrpPtr, kparams.Uint64, irp)
		kevt.AppendParam(kparams.FileObject, kparams.Uint64, fileObject)
		kevt.AppendParam(kparams.FileKey, kparams.Uint64, fileKey)
		kevt.AppendParam(kparams.ThreadID, kparams.TID, tid)
		kevt.AppendParam(kparams.FileOffset, kparams.Uint64, offset)
		kevt.AppendParam(kparams.FileIoSize, kparams.Uint32, size)
	case ktypes.EnumDirectory:
		var (
			irp        uint64
			fileObject uint64
			fileKey    uint64
			tid        uint32
			infoClass  uint32
			filename   string
		)
		if e.Version() >= 2 {
			irp = e.ReadUint64(0)
		}
		if e.Version() >= 3 {
			fileObject = e.ReadUint64(8)
			fileKey = e.ReadUint64(16)
			tid = e.ReadUint32(24)
			infoClass = e.ReadUint32(32)
			filename = e.ConsumeUTF16String(38)
		} else {
			tid = e.ReadUint32(8)
			fileObject = e.ReadUint64(12)
			fileKey = e.ReadUint64(20)
		}
		kevt.AppendParam(kparams.FileIrpPtr, kparams.Uint64, irp)
		kevt.AppendParam(kparams.FileObject, kparams.Uint64, fileObject)
		kevt.AppendParam(kparams.ThreadID, kparams.TID, tid)
		kevt.AppendParam(kparams.FileKey, kparams.Uint64, fileKey)
		kevt.AppendParam(kparams.FileName, kparams.UnicodeString, filename)
		kevt.AppendParam(kparams.FileInfoClass, kparams.Enum, infoClass, WithEnum(fs.FileInfoClasses))
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
		if e.Version() >= 1 {
			pid = e.ReadUint32(0)
			size = e.ReadUint32(4)
			dip = e.ReadUint32(8)
			sip = e.ReadUint32(12)
			dport = e.ReadUint16(16)
			sport = e.ReadUint16(18)
		} else {
			dip = e.ReadUint32(0)
			sip = e.ReadUint32(4)
			dport = e.ReadUint16(8)
			sport = e.ReadUint16(10)
			size = e.ReadUint32(12)
			pid = e.ReadUint32(16)
		}
		kevt.AppendParam(kparams.ProcessID, kparams.PID, pid)
		kevt.AppendParam(kparams.NetSize, kparams.Uint32, size)
		kevt.AppendParam(kparams.NetDIP, kparams.IPv4, dip)
		kevt.AppendParam(kparams.NetSIP, kparams.IPv4, sip)
		kevt.AppendParam(kparams.NetDport, kparams.Port, dport)
		kevt.AppendParam(kparams.NetSport, kparams.Port, sport)
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
		if e.Version() >= 2 {
			pid = e.ReadUint32(0)
			size = e.ReadUint32(4)
			dip = e.ReadBytes(8, 16)
			sip = e.ReadBytes(24, 16)
			dport = e.ReadUint16(40)
			sport = e.ReadUint16(42)
		}

		kevt.AppendParam(kparams.ProcessID, kparams.PID, pid)
		kevt.AppendParam(kparams.NetSize, kparams.Uint32, size)
		kevt.AppendParam(kparams.NetDIP, kparams.IPv6, dip)
		kevt.AppendParam(kparams.NetSIP, kparams.IPv6, sip)
		kevt.AppendParam(kparams.NetDport, kparams.Port, dport)
		kevt.AppendParam(kparams.NetSport, kparams.Port, sport)
	case ktypes.LoadDriver:
		filename := e.ConsumeUTF16String(4)
		kevt.AppendParam(kparams.ImageFilename, kparams.FileDosPath, filename)
	}
}

func joinSID(account, domain string) string { return fmt.Sprintf("%s\\%s", domain, account) }
