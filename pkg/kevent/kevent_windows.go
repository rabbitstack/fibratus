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
	"github.com/rabbitstack/fibratus/pkg/util/filetime"
	"github.com/rabbitstack/fibratus/pkg/util/hashers"
	"github.com/rabbitstack/fibratus/pkg/util/hostname"
	"github.com/rabbitstack/fibratus/pkg/zsyscall"
	"github.com/rabbitstack/fibratus/pkg/zsyscall/etw"
	"golang.org/x/sys/windows"
	"os"
	"strings"
	"unsafe"
)

var (
	// rundowns stores the hashes of processed rundown events
	rundowns   = map[uint64]bool{}
	currentPid = uint32(os.Getpid())
)

// New constructs a fresh event instance with basic fields and parameters. If the published
// ETW event is not recognized as a valid event in our internal types, then we return a nil
// event.
func New(seq uint64, evt *etw.EventRecord) *Kevent {
	var (
		pid        = evt.Header.ProcessID
		tid        = evt.Header.ThreadID
		providerID = evt.Header.ProviderID
		cpu        = *(*uint8)(unsafe.Pointer(&evt.BufferContext.ProcessorIndex[0]))
		ts         = filetime.ToEpoch(evt.Header.Timestamp)
	)
	// build event type from the provider GUID and opcode
	var ktype ktypes.Ktype
	switch providerID {
	case etw.KernelAuditAPICallsGUID, etw.AntimalwareEngineGUID:
		ktype = ktypes.Pack(providerID, uint8(evt.Header.EventDescriptor.ID))
	default:
		ktype = ktypes.Pack(providerID, evt.Header.EventDescriptor.Opcode)
	}
	if !ktype.Exists() {
		return nil
	}
	e := pool.Get().(*Kevent)
	*e = Kevent{
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
	e.produceParams(evt)
	e.normalize()
	return e
}

func (e *Kevent) normalize() {
	switch e.Category {
	case ktypes.Image:
		// sometimes the pid present in event header is invalid
		// but, we can get the valid one from the event parameters
		if e.InvalidPid() {
			e.PID, _ = e.Kparams.GetPid()
		}
	case ktypes.File:
		// on some Windows versions the value of
		// the PID is invalid in the event header
		if e.InvalidPid() {
			// try to resolve a valid pid from thread ID
			threadID, err := e.Kparams.GetTid()
			if err != nil {
				break
			}
			thread, err := windows.OpenThread(windows.THREAD_QUERY_LIMITED_INFORMATION, false, threadID)
			if err != nil {
				return
			}
			defer windows.CloseHandle(thread)
			e.PID = zsyscall.GetProcessIdOfThread(thread)
		}
	case ktypes.Process:
		// process start events may be logged in the context of the parent or child process.
		// As a result, the ProcessId member of EVENT_TRACE_HEADER may not correspond to the
		// process being created, so we set the event pid to be the one of the parent process
		if e.IsCreateProcess() {
			e.PID, _ = e.Kparams.GetPpid()
		}
	case ktypes.Net:
		e.PID, _ = e.Kparams.GetPid()
	}
}

// IsNetworkTCP determines whether the event pertains to network TCP events.
func (e Kevent) IsNetworkTCP() bool {
	return e.Category == ktypes.Net && e.Type != ktypes.RecvUDPv4 && e.Type != ktypes.RecvUDPv6 &&
		e.Type != ktypes.SendUDPv4 && e.Type != ktypes.SendUDPv6
}

// IsNetworkUDP determines whether the event pertains to network UDP events.
func (e Kevent) IsNetworkUDP() bool {
	return e.Type == ktypes.RecvUDPv4 || e.Type == ktypes.RecvUDPv6 || e.Type == ktypes.SendUDPv4 || e.Type == ktypes.SendUDPv6
}

// IsRundown determines if this is a rundown events.
func (e Kevent) IsRundown() bool {
	return e.Type == ktypes.ProcessRundown || e.Type == ktypes.ThreadRundown || e.Type == ktypes.ImageRundown ||
		e.Type == ktypes.FileRundown || e.Type == ktypes.RegKCBRundown
}

// IsRundownProcessed checks if the rundown events was processed
// to discard writing the snapshot state if the process/module is
// already present. This usually happens when we purposely alter
// the tracing session to induce the arrival of rundown events
// by calling into the `etw.SetTraceInformation` Windows API
// function which causes duplicate rundown events.
// For more pointers check `kstream/controller_windows.go`
// and the `etw.SetTraceInformation` API function
func (e Kevent) IsRundownProcessed() bool {
	key := e.RundownKey()
	_, isProcessed := rundowns[key]
	if isProcessed {
		return true
	}
	rundowns[key] = true
	return false
}

func (e Kevent) IsCreateFile() bool       { return e.Type == ktypes.CreateFile }
func (e Kevent) IsCreateProcess() bool    { return e.Type == ktypes.CreateProcess }
func (e Kevent) IsCloseFile() bool        { return e.Type == ktypes.CloseFile }
func (e Kevent) IsCreateHandle() bool     { return e.Type == ktypes.CreateHandle }
func (e Kevent) IsCloseHandle() bool      { return e.Type == ktypes.CloseHandle }
func (e Kevent) IsDeleteFile() bool       { return e.Type == ktypes.DeleteFile }
func (e Kevent) IsEnumDirectory() bool    { return e.Type == ktypes.EnumDirectory }
func (e Kevent) IsTerminateProcess() bool { return e.Type == ktypes.TerminateProcess }
func (e Kevent) IsTerminateThread() bool  { return e.Type == ktypes.TerminateThread }
func (e Kevent) IsUnloadImage() bool      { return e.Type == ktypes.UnloadImage }
func (e Kevent) IsLoadImage() bool        { return e.Type == ktypes.LoadImage }
func (e Kevent) IsFileOpEnd() bool        { return e.Type == ktypes.FileOpEnd }
func (e Kevent) IsRegSetValue() bool      { return e.Type == ktypes.RegSetValue }
func (e Kevent) IsProcessRundown() bool   { return e.Type == ktypes.ProcessRundown }

func (e Kevent) InvalidPid() bool { return e.PID == zsyscall.InvalidProcessPid }
func (e Kevent) CurrentPid() bool { return e.PID == currentPid }

// IsState indicates if this event is only used for state management.
func (e Kevent) IsState() bool { return e.Type.OnlyState() }

func (e Kevent) RundownKey() uint64 {
	switch e.Type {
	case ktypes.ProcessRundown:
		b := make([]byte, 4)
		pid, _ := e.Kparams.GetPid()

		binary.LittleEndian.PutUint32(b, pid)

		return hashers.FnvUint64(b)
	case ktypes.ThreadRundown:
		b := make([]byte, 8)
		pid, _ := e.Kparams.GetPid()
		tid, _ := e.Kparams.GetTid()

		binary.LittleEndian.PutUint32(b, pid)
		binary.LittleEndian.PutUint32(b, tid)

		return hashers.FnvUint64(b)
	case ktypes.ImageRundown:
		pid, _ := e.Kparams.GetPid()
		mod, _ := e.Kparams.GetString(kparams.ImageFilename)
		b := make([]byte, 4+len(mod))

		binary.LittleEndian.PutUint32(b, pid)
		b = append(b, mod...)

		return hashers.FnvUint64(b)
	case ktypes.FileRundown:
		b := make([]byte, 8)
		fileObject, _ := e.Kparams.GetUint64(kparams.FileObject)
		binary.LittleEndian.PutUint64(b, fileObject)

		return hashers.FnvUint64(b)
	case ktypes.RegKCBRundown:
		key, _ := e.Kparams.GetString(kparams.RegKeyName)
		b := make([]byte, 4+len(key))

		binary.LittleEndian.PutUint32(b, e.PID)
		b = append(b, key...)
		return hashers.FnvUint64(b)
	}
	return 0
}

// PartialKey computes the unique hash of the event
// that can be employed to determine if the event
// from the given process and source has been processed
// in the rule sequences.
func (e Kevent) PartialKey() uint64 {
	switch e.Type {
	case ktypes.WriteFile, ktypes.ReadFile:
		b := make([]byte, 12)
		object, _ := e.Kparams.GetUint64(kparams.FileObject)

		binary.LittleEndian.PutUint32(b, e.PID)
		binary.LittleEndian.PutUint64(b, object)

		return hashers.FnvUint64(b)
	case ktypes.CreateFile:
		file, _ := e.Kparams.GetString(kparams.FileName)
		b := make([]byte, 4+len(file))

		binary.LittleEndian.PutUint32(b, e.PID)
		b = append(b, []byte(file)...)

		return hashers.FnvUint64(b)
	case ktypes.OpenProcess:
		b := make([]byte, 8)
		pid, _ := e.Kparams.GetUint32(kparams.ProcessID)
		access, _ := e.Kparams.GetUint32(kparams.DesiredAccess)

		binary.LittleEndian.PutUint32(b, e.PID)
		binary.LittleEndian.PutUint32(b, pid)
		binary.LittleEndian.PutUint32(b, access)
		return hashers.FnvUint64(b)
	case ktypes.OpenThread:
		b := make([]byte, 8)
		tid, _ := e.Kparams.GetUint32(kparams.ThreadID)
		access, _ := e.Kparams.GetUint32(kparams.DesiredAccess)

		binary.LittleEndian.PutUint32(b, e.PID)
		binary.LittleEndian.PutUint32(b, tid)
		binary.LittleEndian.PutUint32(b, access)
		return hashers.FnvUint64(b)
	case ktypes.AcceptTCPv4, ktypes.RecvTCPv4, ktypes.RecvUDPv4:
		b := make([]byte, 10)

		ip, _ := e.Kparams.GetIP(kparams.NetSIP)
		port, _ := e.Kparams.GetUint16(kparams.NetSport)

		binary.LittleEndian.PutUint32(b, e.PID)
		binary.LittleEndian.PutUint32(b, binary.BigEndian.Uint32(ip.To4()))
		binary.LittleEndian.PutUint16(b, port)
		return hashers.FnvUint64(b)
	case ktypes.AcceptTCPv6, ktypes.RecvTCPv6, ktypes.RecvUDPv6:
		b := make([]byte, 22)

		ip, _ := e.Kparams.GetIP(kparams.NetSIP)
		port, _ := e.Kparams.GetUint16(kparams.NetSport)

		binary.LittleEndian.PutUint32(b, e.PID)
		binary.LittleEndian.PutUint64(b, binary.BigEndian.Uint64(ip.To16()[0:8]))
		binary.LittleEndian.PutUint64(b, binary.BigEndian.Uint64(ip.To16()[8:16]))
		binary.LittleEndian.PutUint16(b, port)
		return hashers.FnvUint64(b)
	case ktypes.ConnectTCPv4, ktypes.SendTCPv4, ktypes.SendUDPv4:
		b := make([]byte, 10)

		ip, _ := e.Kparams.GetIP(kparams.NetDIP)
		port, _ := e.Kparams.GetUint16(kparams.NetDport)

		binary.LittleEndian.PutUint32(b, e.PID)
		binary.LittleEndian.PutUint32(b, binary.BigEndian.Uint32(ip.To4()))
		binary.LittleEndian.PutUint16(b, port)
		return hashers.FnvUint64(b)
	case ktypes.ConnectTCPv6, ktypes.SendTCPv6, ktypes.SendUDPv6:
		b := make([]byte, 22)

		ip, _ := e.Kparams.GetIP(kparams.NetDIP)
		port, _ := e.Kparams.GetUint16(kparams.NetDport)

		binary.LittleEndian.PutUint32(b, e.PID)
		binary.LittleEndian.PutUint64(b, binary.BigEndian.Uint64(ip.To16()[0:8]))
		binary.LittleEndian.PutUint64(b, binary.BigEndian.Uint64(ip.To16()[8:16]))
		binary.LittleEndian.PutUint16(b, port)
		return hashers.FnvUint64(b)
	case ktypes.RegOpenKey, ktypes.RegQueryKey, ktypes.RegQueryValue,
		ktypes.RegDeleteKey, ktypes.RegDeleteValue, ktypes.RegSetValue:
		key, _ := e.Kparams.GetString(kparams.RegKeyName)
		b := make([]byte, 4+len(key))

		binary.LittleEndian.PutUint32(b, e.PID)
		b = append(b, key...)
		return hashers.FnvUint64(b)
	}
	return 0
}

// Summary returns a brief summary of this event. Various important substrings
// in the summary text are highlighted by surrounding them inside <code> HTML tags.
func (e *Kevent) Summary() string {
	switch e.Type {
	case ktypes.CreateProcess:
		exe := e.Kparams.MustGetString(kparams.Exe)
		sid := e.Kparams.MustGetString(kparams.UserSID)
		return printSummary(e, fmt.Sprintf("spawned <code>%s</code> process as <code>%s</code> user", exe, sid))
	case ktypes.TerminateProcess:
		exe := e.Kparams.MustGetString(kparams.Exe)
		sid := e.Kparams.MustGetString(kparams.UserSID)
		return printSummary(e, fmt.Sprintf("terminated <code>%s</code> process as <code>%s</code> user", exe, sid))
	case ktypes.OpenProcess:
		access, _ := e.Kparams.GetStringSlice(kparams.DesiredAccessNames)
		exe, _ := e.Kparams.GetString(kparams.Exe)
		return printSummary(e, fmt.Sprintf("opened <code>%s</code> process object with <code>%s</code> access right(s)",
			exe, strings.Join(access, "|")))
	case ktypes.CreateThread:
		tid, _ := e.Kparams.GetTid()
		addr, _ := e.Kparams.GetHex(kparams.StartAddr)
		return printSummary(e, fmt.Sprintf("spawned a new thread with <code>%d</code> id at <code>%s</code> address",
			tid, addr))
	case ktypes.TerminateThread:
		tid, _ := e.Kparams.GetTid()
		addr, _ := e.Kparams.GetHex(kparams.StartAddr)
		return printSummary(e, fmt.Sprintf("terminated a thread with <code>%d</code> id at <code>%s</code> address",
			tid, addr))
	case ktypes.OpenThread:
		access, _ := e.Kparams.GetStringSlice(kparams.DesiredAccessNames)
		exe, _ := e.Kparams.GetString(kparams.Exe)
		return printSummary(e, fmt.Sprintf("opened <code>%s</code> process' thread object with <code>%s</code> access right(s)",
			exe, strings.Join(access, "|")))
	case ktypes.LoadImage:
		filename, _ := e.Kparams.GetString(kparams.FileName)
		return printSummary(e, fmt.Sprintf("loaded </code>%s</code> module", filename))
	case ktypes.UnloadImage:
		filename, _ := e.Kparams.GetString(kparams.FileName)
		return printSummary(e, fmt.Sprintf("unloaded </code>%s</code> module", filename))
	case ktypes.CreateFile:
		op := e.GetParamAsString(kparams.FileOperation)
		filename := e.Kparams.MustGetString(kparams.FileName)
		return printSummary(e, fmt.Sprintf("%sed a file <code>%s</code>", strings.ToLower(op), filename))
	case ktypes.ReadFile:
		filename, _ := e.Kparams.GetString(kparams.FileName)
		size, _ := e.Kparams.GetUint32(kparams.FileIoSize)
		return printSummary(e, fmt.Sprintf("read <code>%d</code> bytes from <code>%s</code> file", size, filename))
	case ktypes.WriteFile:
		filename, _ := e.Kparams.GetString(kparams.FileName)
		size, _ := e.Kparams.GetUint32(kparams.FileIoSize)
		return printSummary(e, fmt.Sprintf("wrote <code>%d</code> bytes to <code>%s</code> file", size, filename))
	case ktypes.SetFileInformation:
		filename, _ := e.Kparams.GetString(kparams.FileName)
		class, _ := e.Kparams.GetString(kparams.FileInfoClass)
		return printSummary(e, fmt.Sprintf("set <code>%s</code> information class on <code>%s</code> file", class, filename))
	case ktypes.DeleteFile:
		filename, _ := e.Kparams.GetString(kparams.FileName)
		return printSummary(e, fmt.Sprintf("deleted <code>%s</code> file", filename))
	case ktypes.RenameFile:
		filename, _ := e.Kparams.GetString(kparams.FileName)
		return printSummary(e, fmt.Sprintf("renamed <code>%s</code> file", filename))
	case ktypes.CloseFile:
		filename, _ := e.Kparams.GetString(kparams.FileName)
		return printSummary(e, fmt.Sprintf("closed <code>%s</code> file", filename))
	case ktypes.EnumDirectory:
		filename, _ := e.Kparams.GetString(kparams.FileName)
		return printSummary(e, fmt.Sprintf("enumerated <code>%s</code> directory", filename))
	case ktypes.RegCreateKey:
		key, _ := e.Kparams.GetString(kparams.RegKeyName)
		return printSummary(e, fmt.Sprintf("created <code>%s</code> key", key))
	case ktypes.RegOpenKey:
		key, _ := e.Kparams.GetString(kparams.RegKeyName)
		return printSummary(e, fmt.Sprintf("opened <code>%s</code> key", key))
	case ktypes.RegDeleteKey:
		key, _ := e.Kparams.GetString(kparams.RegKeyName)
		return printSummary(e, fmt.Sprintf("deleted <code>%s</code> key", key))
	case ktypes.RegQueryKey:
		key, _ := e.Kparams.GetString(kparams.RegKeyName)
		return printSummary(e, fmt.Sprintf("queried <code>%s</code> key", key))
	case ktypes.RegSetValue:
		key, _ := e.Kparams.GetString(kparams.RegKeyName)
		val, err := e.Kparams.GetString(kparams.RegValue)
		if err != nil {
			return printSummary(e, fmt.Sprintf("set <code>%s</code> value", key))
		}
		return printSummary(e, fmt.Sprintf("set <code>%s</code> payload in <code>%s</code> value", val, key))
	case ktypes.RegDeleteValue:
		key, _ := e.Kparams.GetString(kparams.RegKeyName)
		return printSummary(e, fmt.Sprintf("deleted <code>%s</code> value", key))
	case ktypes.RegQueryValue:
		key, _ := e.Kparams.GetString(kparams.RegKeyName)
		return printSummary(e, fmt.Sprintf("queried <code>%s</code> value", key))
	case ktypes.AcceptTCPv4, ktypes.AcceptTCPv6:
		ip, _ := e.Kparams.GetIP(kparams.NetSIP)
		port, _ := e.Kparams.GetUint16(kparams.NetSport)
		return printSummary(e, fmt.Sprintf("accepted connection from <code>%v</code> and <code>%d</code> port", ip, port))
	case ktypes.ConnectTCPv4, ktypes.ConnectTCPv6:
		ip, _ := e.Kparams.GetIP(kparams.NetDIP)
		port, _ := e.Kparams.GetUint16(kparams.NetDport)
		return printSummary(e, fmt.Sprintf("connected to <code>%v</code> and <code>%d</code> port", ip, port))
	case ktypes.SendTCPv4, ktypes.SendTCPv6, ktypes.SendUDPv4, ktypes.SendUDPv6:
		ip, _ := e.Kparams.GetIP(kparams.NetDIP)
		port, _ := e.Kparams.GetUint16(kparams.NetDport)
		size, _ := e.Kparams.GetUint32(kparams.NetSize)
		return printSummary(e, fmt.Sprintf("sent <code>%d</code> bytes to <code>%v</code> and <code>%d</code> port",
			size, ip, port))
	case ktypes.RecvTCPv4, ktypes.RecvTCPv6, ktypes.RecvUDPv4, ktypes.RecvUDPv6:
		ip, _ := e.Kparams.GetIP(kparams.NetSIP)
		port, _ := e.Kparams.GetUint16(kparams.NetSport)
		size, _ := e.Kparams.GetUint32(kparams.NetSize)
		return printSummary(e, fmt.Sprintf("received <code>%d</code> bytes from <code>%v</code> and <code>%d</code> port",
			size, ip, port))
	case ktypes.CreateHandle:
		handleType, _ := e.Kparams.GetString(kparams.HandleObjectTypeName)
		handleName, _ := e.Kparams.GetString(kparams.HandleObjectName)
		return printSummary(e, fmt.Sprintf("created <code>%s</code> handle of <code>%s</code> type",
			handleName, handleType))
	case ktypes.CloseHandle:
		handleType, _ := e.Kparams.GetString(kparams.HandleObjectTypeName)
		handleName, _ := e.Kparams.GetString(kparams.HandleObjectName)
		return printSummary(e, fmt.Sprintf("closed <code>%s</code> handle of <code>%s</code> type",
			handleName, handleType))
	case ktypes.LoadDriver:
		driver, _ := e.Kparams.GetString(kparams.ImageFilename)
		return printSummary(e, fmt.Sprintf("loaded <code>%s</code> driver", driver))
	}
	return ""
}

func printSummary(e *Kevent, text string) string {
	ps := e.PS
	if ps != nil {
		return fmt.Sprintf("<code>%s</code> %s", ps.Name, text)
	}
	return fmt.Sprintf("process with <code>%d</code> id %s", e.PID, text)
}
