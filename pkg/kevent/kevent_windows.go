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
	"encoding/binary"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
	"github.com/rabbitstack/fibratus/pkg/util/filetime"
	"github.com/rabbitstack/fibratus/pkg/util/hashers"
	"github.com/rabbitstack/fibratus/pkg/util/hostname"
	"strings"
	"unsafe"
)

var rundowns = map[uint64]bool{}

// New constructs a fresh event instance with basic fields and parameters.
func New(seq uint64, ktype ktypes.Ktype, evt *etw.EventRecord) *Kevent {
	var (
		pid = evt.Header.ProcessID
		tid = evt.Header.ThreadID
		cpu = *(*uint8)(unsafe.Pointer(&evt.BufferContext.ProcessorIndex[0]))
		ts  = filetime.ToEpoch(evt.Header.Timestamp)
	)
	kevt := pool.Get().(*Kevent)
	*kevt = Kevent{
		Seq:         seq,
		PID:         pid,
		Tid:         tid,
		CPU:         cpu,
		Type:        ktype,
		Category:    ktype.Category(),
		Name:        ktype.String(),
		Kparams:     make(map[string]*Kparam),
		Description: ktype.Description(),
		Timestamp:   ts,
		Metadata:    make(map[MetadataKey]string),
		Host:        hostname.Get(),
	}
	kevt.produceParams(evt)
	return kevt
}

// IsNetworkTCP determines whether the event pertains to network TCP events.
func (kevt Kevent) IsNetworkTCP() bool {
	return kevt.Category == ktypes.Net && kevt.Type != ktypes.RecvUDPv4 && kevt.Type != ktypes.RecvUDPv6 &&
		kevt.Type != ktypes.SendUDPv4 && kevt.Type != ktypes.SendUDPv6
}

// IsNetworkUDP determines whether the event pertains to network UDP events.
func (kevt Kevent) IsNetworkUDP() bool {
	return kevt.Type == ktypes.RecvUDPv4 || kevt.Type == ktypes.RecvUDPv6 || kevt.Type == ktypes.SendUDPv4 || kevt.Type == ktypes.SendUDPv6
}

// IsRundown determines if this is a rundown events.
func (kevt Kevent) IsRundown() bool {
	return kevt.Type == ktypes.ProcessRundown || kevt.Type == ktypes.ThreadRundown || kevt.Type == ktypes.ImageRundown ||
		kevt.Type == ktypes.FileRundown || kevt.Type == ktypes.RegKCBRundown
}

func (kevt Kevent) IsRundownProcessed() bool {
	key := kevt.RundownKey()
	if kevt.IsRundown() && !rundowns[key] {
		rundowns[key] = true
		return false
	}
	return kevt.IsRundown() && rundowns[key]
}

// IsCreateFile indicates if this event is creating/opening a file.
func (kevt Kevent) IsCreateFile() bool { return kevt.Type == ktypes.CreateFile }

func (kevt Kevent) IsCloseFile() bool { return kevt.Type == ktypes.CloseFile }

func (kevt Kevent) IsDeleteFile() bool { return kevt.Type == ktypes.DeleteFile }

func (kevt Kevent) IsEnumDirectory() bool { return kevt.Type == ktypes.EnumDirectory }

func (kevt Kevent) IsTerminateProcess() bool { return kevt.Type == ktypes.TerminateProcess }

func (kevt Kevent) IsTerminateThread() bool { return kevt.Type == ktypes.TerminateThread }

func (kevt Kevent) IsUnloadImage() bool { return kevt.Type == ktypes.UnloadImage }

func (kevt Kevent) IsFileOpEnd() bool { return kevt.Type == ktypes.FileOpEnd }

func (kevt Kevent) IsRegSetValue() bool { return kevt.Type == ktypes.RegSetValue }

func (kevt Kevent) InvalidPid() bool { return kevt.PID == 0xffffffff }

// IsState indicates if this event is only used for state management.
func (kevt Kevent) IsState() bool { return kevt.Type.OnlyState() }

func (kevt Kevent) RundownKey() uint64 {
	return 0
}

// PartialKey computes the unique hash of the event
// that can be employed to determine if the event
// from the given process and source has been processed
// in the rule sequences.
func (kevt Kevent) PartialKey() uint64 {
	switch kevt.Type {
	case ktypes.WriteFile, ktypes.ReadFile:
		b := make([]byte, 12)
		object, _ := kevt.Kparams.GetUint64(kparams.FileObject)

		binary.LittleEndian.PutUint32(b, kevt.PID)
		binary.LittleEndian.PutUint64(b, object)

		return hashers.FnvUint64(b)
	case ktypes.CreateFile:
		file, _ := kevt.Kparams.GetString(kparams.FileName)
		b := make([]byte, 4+len(file))

		binary.LittleEndian.PutUint32(b, kevt.PID)
		b = append(b, []byte(file)...)

		return hashers.FnvUint64(b)
	case ktypes.OpenProcess:
		b := make([]byte, 8)
		pid, _ := kevt.Kparams.GetUint32(kparams.ProcessID)
		access, _ := kevt.Kparams.GetUint32(kparams.DesiredAccess)

		binary.LittleEndian.PutUint32(b, kevt.PID)
		binary.LittleEndian.PutUint32(b, pid)
		binary.LittleEndian.PutUint32(b, access)
		return hashers.FnvUint64(b)
	case ktypes.OpenThread:
		b := make([]byte, 8)
		tid, _ := kevt.Kparams.GetUint32(kparams.ThreadID)
		access, _ := kevt.Kparams.GetUint32(kparams.DesiredAccess)

		binary.LittleEndian.PutUint32(b, kevt.PID)
		binary.LittleEndian.PutUint32(b, tid)
		binary.LittleEndian.PutUint32(b, access)
		return hashers.FnvUint64(b)
	case ktypes.AcceptTCPv4, ktypes.RecvTCPv4, ktypes.RecvUDPv4:
		b := make([]byte, 10)

		ip, _ := kevt.Kparams.GetIP(kparams.NetSIP)
		port, _ := kevt.Kparams.GetUint16(kparams.NetSport)

		binary.LittleEndian.PutUint32(b, kevt.PID)
		binary.LittleEndian.PutUint32(b, binary.BigEndian.Uint32(ip.To4()))
		binary.LittleEndian.PutUint16(b, port)
		return hashers.FnvUint64(b)
	case ktypes.AcceptTCPv6, ktypes.RecvTCPv6, ktypes.RecvUDPv6:
		b := make([]byte, 22)

		ip, _ := kevt.Kparams.GetIP(kparams.NetSIP)
		port, _ := kevt.Kparams.GetUint16(kparams.NetSport)

		binary.LittleEndian.PutUint32(b, kevt.PID)
		binary.LittleEndian.PutUint64(b, binary.BigEndian.Uint64(ip.To16()[0:8]))
		binary.LittleEndian.PutUint64(b, binary.BigEndian.Uint64(ip.To16()[8:16]))
		binary.LittleEndian.PutUint16(b, port)
		return hashers.FnvUint64(b)
	case ktypes.ConnectTCPv4, ktypes.SendTCPv4, ktypes.SendUDPv4:
		b := make([]byte, 10)

		ip, _ := kevt.Kparams.GetIP(kparams.NetDIP)
		port, _ := kevt.Kparams.GetUint16(kparams.NetDport)

		binary.LittleEndian.PutUint32(b, kevt.PID)
		binary.LittleEndian.PutUint32(b, binary.BigEndian.Uint32(ip.To4()))
		binary.LittleEndian.PutUint16(b, port)
		return hashers.FnvUint64(b)
	case ktypes.ConnectTCPv6, ktypes.SendTCPv6, ktypes.SendUDPv6:
		b := make([]byte, 22)

		ip, _ := kevt.Kparams.GetIP(kparams.NetDIP)
		port, _ := kevt.Kparams.GetUint16(kparams.NetDport)

		binary.LittleEndian.PutUint32(b, kevt.PID)
		binary.LittleEndian.PutUint64(b, binary.BigEndian.Uint64(ip.To16()[0:8]))
		binary.LittleEndian.PutUint64(b, binary.BigEndian.Uint64(ip.To16()[8:16]))
		binary.LittleEndian.PutUint16(b, port)
		return hashers.FnvUint64(b)
	case ktypes.RegOpenKey, ktypes.RegQueryKey, ktypes.RegQueryValue,
		ktypes.RegDeleteKey, ktypes.RegDeleteValue, ktypes.RegSetValue:
		key, _ := kevt.Kparams.GetString(kparams.RegKeyName)
		b := make([]byte, 4+len(key))

		binary.LittleEndian.PutUint32(b, kevt.PID)
		b = append(b, key...)
		return hashers.FnvUint64(b)
	}
	return 0
}

// Summary returns a brief summary of this event. Various important substrings
// in the summary text are highlighted by surrounding them inside <code> HTML tags.
func (kevt *Kevent) Summary() string {
	switch kevt.Type {
	case ktypes.CreateProcess:
		exe := kevt.Kparams.MustGetString(kparams.Exe)
		sid := kevt.Kparams.MustGetString(kparams.UserSID)
		return printSummary(kevt, fmt.Sprintf("spawned <code>%s</code> process as <code>%s</code> user", exe, sid))
	case ktypes.TerminateProcess:
		exe := kevt.Kparams.MustGetString(kparams.Exe)
		sid := kevt.Kparams.MustGetString(kparams.UserSID)
		return printSummary(kevt, fmt.Sprintf("terminated <code>%s</code> process as <code>%s</code> user", exe, sid))
	case ktypes.OpenProcess:
		access, _ := kevt.Kparams.GetStringSlice(kparams.DesiredAccessNames)
		exe, _ := kevt.Kparams.GetString(kparams.Exe)
		return printSummary(kevt, fmt.Sprintf("opened <code>%s</code> process object with <code>%s</code> access right(s)",
			exe, strings.Join(access, "|")))
	case ktypes.CreateThread:
		tid, _ := kevt.Kparams.GetTid()
		addr, _ := kevt.Kparams.GetHex(kparams.StartAddr)
		return printSummary(kevt, fmt.Sprintf("spawned a new thread with <code>%d</code> id at <code>%s</code> address",
			tid, addr))
	case ktypes.TerminateThread:
		tid, _ := kevt.Kparams.GetTid()
		addr, _ := kevt.Kparams.GetHex(kparams.StartAddr)
		return printSummary(kevt, fmt.Sprintf("terminated a thread with <code>%d</code> id at <code>%s</code> address",
			tid, addr))
	case ktypes.OpenThread:
		access, _ := kevt.Kparams.GetStringSlice(kparams.DesiredAccessNames)
		exe, _ := kevt.Kparams.GetString(kparams.Exe)
		return printSummary(kevt, fmt.Sprintf("opened <code>%s</code> process' thread object with <code>%s</code> access right(s)",
			exe, strings.Join(access, "|")))
	case ktypes.LoadImage:
		filename, _ := kevt.Kparams.GetString(kparams.FileName)
		return printSummary(kevt, fmt.Sprintf("loaded </code>%s</code> module", filename))
	case ktypes.UnloadImage:
		filename, _ := kevt.Kparams.GetString(kparams.FileName)
		return printSummary(kevt, fmt.Sprintf("unloaded </code>%s</code> module", filename))
	case ktypes.CreateFile:
		op := kevt.GetParamAsString(kparams.FileOperation)
		filename := kevt.Kparams.MustGetString(kparams.FileName)
		return printSummary(kevt, fmt.Sprintf("%sed a file <code>%s</code>", strings.ToLower(op), filename))
	case ktypes.ReadFile:
		filename, _ := kevt.Kparams.GetString(kparams.FileName)
		size, _ := kevt.Kparams.GetUint32(kparams.FileIoSize)
		return printSummary(kevt, fmt.Sprintf("read <code>%d</code> bytes from <code>%s</code> file", size, filename))
	case ktypes.WriteFile:
		filename, _ := kevt.Kparams.GetString(kparams.FileName)
		size, _ := kevt.Kparams.GetUint32(kparams.FileIoSize)
		return printSummary(kevt, fmt.Sprintf("wrote <code>%d</code> bytes to <code>%s</code> file", size, filename))
	case ktypes.SetFileInformation:
		filename, _ := kevt.Kparams.GetString(kparams.FileName)
		class, _ := kevt.Kparams.GetString(kparams.FileInfoClass)
		return printSummary(kevt, fmt.Sprintf("set <code>%s</code> information class on <code>%s</code> file", class, filename))
	case ktypes.DeleteFile:
		filename, _ := kevt.Kparams.GetString(kparams.FileName)
		return printSummary(kevt, fmt.Sprintf("deleted <code>%s</code> file", filename))
	case ktypes.RenameFile:
		filename, _ := kevt.Kparams.GetString(kparams.FileName)
		return printSummary(kevt, fmt.Sprintf("renamed <code>%s</code> file", filename))
	case ktypes.CloseFile:
		filename, _ := kevt.Kparams.GetString(kparams.FileName)
		return printSummary(kevt, fmt.Sprintf("closed <code>%s</code> file", filename))
	case ktypes.EnumDirectory:
		filename, _ := kevt.Kparams.GetString(kparams.FileName)
		return printSummary(kevt, fmt.Sprintf("enumerated <code>%s</code> directory", filename))
	case ktypes.RegCreateKey:
		key, _ := kevt.Kparams.GetString(kparams.RegKeyName)
		return printSummary(kevt, fmt.Sprintf("created <code>%s</code> key", key))
	case ktypes.RegOpenKey:
		key, _ := kevt.Kparams.GetString(kparams.RegKeyName)
		return printSummary(kevt, fmt.Sprintf("opened <code>%s</code> key", key))
	case ktypes.RegDeleteKey:
		key, _ := kevt.Kparams.GetString(kparams.RegKeyName)
		return printSummary(kevt, fmt.Sprintf("deleted <code>%s</code> key", key))
	case ktypes.RegQueryKey:
		key, _ := kevt.Kparams.GetString(kparams.RegKeyName)
		return printSummary(kevt, fmt.Sprintf("queried <code>%s</code> key", key))
	case ktypes.RegSetValue:
		key, _ := kevt.Kparams.GetString(kparams.RegKeyName)
		val, err := kevt.Kparams.GetString(kparams.RegValue)
		if err != nil {
			return printSummary(kevt, fmt.Sprintf("set <code>%s</code> value", key))
		}
		return printSummary(kevt, fmt.Sprintf("set <code>%s</code> payload in <code>%s</code> value", val, key))
	case ktypes.RegDeleteValue:
		key, _ := kevt.Kparams.GetString(kparams.RegKeyName)
		return printSummary(kevt, fmt.Sprintf("deleted <code>%s</code> value", key))
	case ktypes.RegQueryValue:
		key, _ := kevt.Kparams.GetString(kparams.RegKeyName)
		return printSummary(kevt, fmt.Sprintf("queried <code>%s</code> value", key))
	case ktypes.AcceptTCPv4, ktypes.AcceptTCPv6:
		ip, _ := kevt.Kparams.GetIP(kparams.NetSIP)
		port, _ := kevt.Kparams.GetUint16(kparams.NetSport)
		return printSummary(kevt, fmt.Sprintf("accepted connection from <code>%v</code> and <code>%d</code> port", ip, port))
	case ktypes.ConnectTCPv4, ktypes.ConnectTCPv6:
		ip, _ := kevt.Kparams.GetIP(kparams.NetDIP)
		port, _ := kevt.Kparams.GetUint16(kparams.NetDport)
		return printSummary(kevt, fmt.Sprintf("connected to <code>%v</code> and <code>%d</code> port", ip, port))
	case ktypes.SendTCPv4, ktypes.SendTCPv6, ktypes.SendUDPv4, ktypes.SendUDPv6:
		ip, _ := kevt.Kparams.GetIP(kparams.NetDIP)
		port, _ := kevt.Kparams.GetUint16(kparams.NetDport)
		size, _ := kevt.Kparams.GetUint32(kparams.NetSize)
		return printSummary(kevt, fmt.Sprintf("sent <code>%d</code> bytes to <code>%v</code> and <code>%d</code> port",
			size, ip, port))
	case ktypes.RecvTCPv4, ktypes.RecvTCPv6, ktypes.RecvUDPv4, ktypes.RecvUDPv6:
		ip, _ := kevt.Kparams.GetIP(kparams.NetSIP)
		port, _ := kevt.Kparams.GetUint16(kparams.NetSport)
		size, _ := kevt.Kparams.GetUint32(kparams.NetSize)
		return printSummary(kevt, fmt.Sprintf("received <code>%d</code> bytes from <code>%v</code> and <code>%d</code> port",
			size, ip, port))
	case ktypes.CreateHandle:
		handleType, _ := kevt.Kparams.GetString(kparams.HandleObjectTypeName)
		handleName, _ := kevt.Kparams.GetString(kparams.HandleObjectName)
		return printSummary(kevt, fmt.Sprintf("created <code>%s</code> handle of <code>%s</code> type",
			handleName, handleType))
	case ktypes.CloseHandle:
		handleType, _ := kevt.Kparams.GetString(kparams.HandleObjectTypeName)
		handleName, _ := kevt.Kparams.GetString(kparams.HandleObjectName)
		return printSummary(kevt, fmt.Sprintf("closed <code>%s</code> handle of <code>%s</code> type",
			handleName, handleType))
	case ktypes.LoadDriver:
		driver, _ := kevt.Kparams.GetString(kparams.ImageFilename)
		return printSummary(kevt, fmt.Sprintf("loaded <code>%s</code> driver", driver))
	}
	return ""
}

func printSummary(kevt *Kevent, text string) string {
	ps := kevt.PS
	if ps != nil {
		return fmt.Sprintf("<code>%s</code> %s", ps.Name, text)
	}
	return fmt.Sprintf("process with <code>%d</code> id %s", kevt.PID, text)
}
