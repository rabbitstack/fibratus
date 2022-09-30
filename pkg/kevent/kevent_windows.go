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
	case ktypes.WriteFile, ktypes.ReadFile, ktypes.CreateFile:
		h := fnv.New64()

		b := make([]byte, 12)
		binary.LittleEndian.PutUint32(b, kevt.PID)
		file, _ := kevt.Kparams.GetUint64(kparams.FileObject)
		binary.LittleEndian.PutUint64(b, file)
		_, _ = h.Write(b)

		return h.Sum64()
	}
	return 0
}
