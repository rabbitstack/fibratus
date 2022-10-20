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
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"hash/fnv"
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
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, kevt.PID)
		pid, _ := kevt.Kparams.GetUint32(kparams.ProcessID)

		binary.LittleEndian.PutUint32(b, kevt.PID)
		binary.LittleEndian.PutUint32(b, pid)
		return fnvHash(b)
	}
	return 0
}

func fnvHash(b []byte) uint64 {
	h := fnv.New64()
	_, _ = h.Write(b)
	return h.Sum64()
}
