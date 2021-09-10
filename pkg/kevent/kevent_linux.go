/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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
)

// Header describes the layout of the event header
// that is pushed to the perf ring buffer.
type Header struct {
	// Timestamp expressed in nanoseconds since epoch
	Timestamp uint64
	// Pid is the process identifer that produced the event
	Pid uint32
	// Tid is the thread identifier that produced the event
	Tid uint32
	// CPU core on which the event was generated
	CPU uint32
	// Nparams represents the number of parameters for particular event
	Nparams uint32
	// Type indicates the event type which is usually the syscall number
	Type uint16
}

// HeaderFromRawSample constructs the event header from perf raw sample.
func HeaderFromRawSample(rawSample []byte) *Header {
	var header = new(Header)
	header.Timestamp = binary.LittleEndian.Uint64(rawSample[0:])
	header.Pid = binary.LittleEndian.Uint32(rawSample[8:])
	header.Tid = binary.LittleEndian.Uint32(rawSample[12:])
	header.CPU = binary.LittleEndian.Uint32(rawSample[16:])
	header.Nparams = binary.LittleEndian.Uint32(rawSample[20:])
	header.Type = binary.LittleEndian.Uint16(rawSample[24:])
	return header
}

// String returns the raw string representation of the event header.
func (h Header) String() string {
	return fmt.Sprintf(
		`
		Timestamp: %d
		Pid: %d
		Tid: %d
		CPU: %d
		Nparams: %d
		Type: %d`,
		h.Timestamp,
		h.Pid,
		h.Tid,
		h.CPU,
		h.Nparams,
		h.Type,
	)
}

func NewFromKcap(buf []byte) (*Kevent, error) {
	return nil, nil
}
