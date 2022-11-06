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
	"hash/fnv"
	"strings"
)

// IsNetworkTCP determines whether the kevent pertains to network TCP events.
func (kevt Kevent) IsNetworkTCP() bool {
	return kevt.Category == ktypes.Net && kevt.Type != ktypes.RecvUDPv4 && kevt.Type != ktypes.RecvUDPv6 && kevt.Type != ktypes.SendUDPv4 && kevt.Type != ktypes.SendUDPv6
}

// IsNetworkUDP determines whether the kevent pertains to network UDP events.
func (kevt Kevent) IsNetworkUDP() bool {
	return kevt.Type == ktypes.RecvUDPv4 || kevt.Type == ktypes.RecvUDPv6 || kevt.Type == ktypes.SendUDPv4 || kevt.Type == ktypes.SendUDPv6
}

// PartialKey computes the unique hash of the event
// that can be employed for determining if the event
// from the given process and source has been processed
// in the rule sequences.
func (kevt Kevent) PartialKey() uint64 {
	switch kevt.Type {
	case ktypes.WriteFile, ktypes.ReadFile:
		b := make([]byte, 12)
		object, _ := kevt.Kparams.GetUint64(kparams.FileObject)

		binary.LittleEndian.PutUint32(b, kevt.PID)
		binary.LittleEndian.PutUint64(b, object)

		return fnvHash(b)
	case ktypes.CreateFile:
		file, _ := kevt.Kparams.GetString(kparams.FileName)
		b := make([]byte, 4+len(file))

		binary.LittleEndian.PutUint32(b, kevt.PID)
		b = append(b, []byte(file)...)

		return fnvHash(b)
	case ktypes.OpenProcess:
		b := make([]byte, 8)
		pid, _ := kevt.Kparams.GetUint32(kparams.ProcessID)
		access, _ := kevt.Kparams.GetUint32(kparams.DesiredAccess)

		binary.LittleEndian.PutUint32(b, kevt.PID)
		binary.LittleEndian.PutUint32(b, pid)
		binary.LittleEndian.PutUint32(b, access)
		return fnvHash(b)
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
		addr, _ := kevt.Kparams.GetHex(kparams.ThreadEntrypoint)
		return printSummary(kevt, fmt.Sprintf("spawned a new thread with <code>%d</code> id at <code>%s</code> address",
			tid, addr))
	case ktypes.TerminateThread:
		tid, _ := kevt.Kparams.GetTid()
		addr, _ := kevt.Kparams.GetHex(kparams.ThreadEntrypoint)
		return printSummary(kevt, fmt.Sprintf("terminated a thread with <code>%d</code> id at <code>%s</code> address",
			tid, addr))
	case ktypes.OpenThread:
		access, _ := kevt.Kparams.GetStringSlice(kparams.DesiredAccessNames)
		exe, _ := kevt.Kparams.GetString(kparams.Exe)
		return printSummary(kevt, fmt.Sprintf("opened <code>%s</code> process' thread object with <code>%s</code> access right(s)",
			exe, strings.Join(access, "|")))
	case ktypes.CreateFile:
		op := kevt.Kparams.MustGetFileOperation()
		filename := kevt.Kparams.MustGetString(kparams.FileName)
		return printSummary(kevt, fmt.Sprintf("%sed a file <code>%s</code>", op, filename))
	case ktypes.WriteFile:
		filename, _ := kevt.Kparams.GetString(kparams.FileName)
		size, _ := kevt.Kparams.GetUint32(kparams.FileIoSize)
		return printSummary(kevt, fmt.Sprintf("wrote <code>%d</code> bytes to <code>%s</code> file", size, filename))
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

func fnvHash(b []byte) uint64 {
	h := fnv.New64()
	_, _ = h.Write(b)
	return h.Sum64()
}
