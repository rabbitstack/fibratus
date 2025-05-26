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

package types

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/cap/section"
	capver "github.com/rabbitstack/fibratus/pkg/cap/version"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	"github.com/rabbitstack/fibratus/pkg/util/convert"
	"time"
	"unsafe"
)

// Marshal produces a byte stream of the process state for writing to the capture file.
func (ps *PS) Marshal() []byte {
	b := make([]byte, 0)

	// write pid and ppid
	b = append(b, bytes.WriteUint32(ps.PID)...)
	b = append(b, bytes.WriteUint32(ps.Ppid)...)

	// write process name
	b = append(b, bytes.WriteUint16(uint16(len(ps.Name)))...)
	b = append(b, ps.Name...)
	// write process command line
	b = append(b, bytes.WriteUint16(uint16(len(ps.Cmdline)))...)
	b = append(b, ps.Cmdline...)
	// write full executable path
	b = append(b, bytes.WriteUint16(uint16(len(ps.Exe)))...)
	b = append(b, ps.Exe...)
	// write current working directory
	b = append(b, bytes.WriteUint16(uint16(len(ps.Cwd)))...)
	b = append(b, ps.Cwd...)
	// write SID
	b = append(b, bytes.WriteUint16(uint16(len(ps.SID)))...)
	b = append(b, ps.SID...)

	// write args
	b = append(b, bytes.WriteUint16(uint16(len(ps.Args)))...)
	for _, arg := range ps.Args {
		b = append(b, bytes.WriteUint16(uint16(len(arg)))...)
		b = append(b, arg...)
	}

	// write session ID
	b = append(b, bytes.WriteUint32(ps.SessionID)...)

	// write env vars block
	b = append(b, bytes.WriteUint16(uint16(len(ps.Envs)))...)
	for k, v := range ps.Envs {
		b = append(b, bytes.WriteUint16(uint16(len(k)))...)
		b = append(b, k...)
		b = append(b, bytes.WriteUint16(uint16(len(v)))...)
		b = append(b, v...)
	}

	// write handles
	sec := section.New(section.Handle, capver.HandleSecV1, uint32(len(ps.Handles)), 0)
	b = append(b, sec[:]...)
	for _, handle := range ps.Handles {
		buf := handle.Marshal()
		b = append(b, bytes.WriteUint16(handle.Offset())...)
		b = append(b, buf...)
	}

	// write the PE metadata
	if ps.PE != nil {
		buf := ps.PE.Marshal()
		sec := section.New(section.PE, capver.PESecV2, 0, uint32(len(buf)))
		b = append(b, sec[:]...)
		b = append(b, buf...)
	} else {
		sec := section.New(section.PE, capver.PESecV2, 0, 0)
		b = append(b, sec[:]...)
	}

	// write start time
	timestamp := make([]byte, 0)
	timestamp = ps.StartTime.AppendFormat(timestamp, time.RFC3339Nano)
	b = append(b, bytes.WriteUint16(uint16(len(timestamp)))...)
	b = append(b, timestamp...)

	// write UUID
	b = append(b, bytes.WriteUint64(ps.uuid)...)

	// write username
	b = append(b, bytes.WriteUint16(uint16(len(ps.Username)))...)
	b = append(b, ps.Username...)

	// write domain
	b = append(b, bytes.WriteUint16(uint16(len(ps.Domain)))...)
	b = append(b, ps.Domain...)

	// write process flags
	b = append(b, convert.Btoi(ps.IsWOW64))
	b = append(b, convert.Btoi(ps.IsPackaged))
	b = append(b, convert.Btoi(ps.IsProtected))

	return b
}

// Unmarshal recovers the process' state from the capture file.
func (ps *PS) Unmarshal(b []byte, psec section.Section) error {
	if len(b) < 8 {
		return fmt.Errorf("expected at least 8 bytes but got %d bytes", len(b))
	}
	var offset uint32

	// read pid/ppid
	ps.PID = bytes.ReadUint32(b[0:])
	ps.Ppid = bytes.ReadUint32(b[4:])

	// read process image name
	l := bytes.ReadUint16(b[8:])
	buf := b[10:]
	offset = uint32(l)
	ps.Name = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read process cmdline
	l = bytes.ReadUint16(b[10+offset:])
	buf = b[12+offset:]
	offset += uint32(l)
	ps.Cmdline = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read full image path
	l = bytes.ReadUint16(b[12+offset:])
	buf = b[14+offset:]
	offset += uint32(l)
	ps.Exe = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read current working directory
	l = bytes.ReadUint16(b[14+offset:])
	buf = b[16+offset:]
	offset += uint32(l)
	ps.Cwd = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read the SID
	l = bytes.ReadUint16(b[16+offset:])
	buf = b[18+offset:]
	offset += uint32(l)
	if len(buf) > 0 {
		ps.SID = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])
	}

	// read args
	nargs := bytes.ReadUint16(b[18+offset:])
	var aoffset uint16
	for i := 0; i < int(nargs); i++ {
		l := bytes.ReadUint16(b[20+offset+uint32(aoffset):])
		buf = b[22+offset+uint32(aoffset):]
		ps.Args = append(ps.Args, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
		aoffset += 2 + l
	}

	offset += uint32(aoffset)
	idx := uint32(20)
	// read session ID
	if psec.Version() >= capver.ProcessSecV3 {
		// session identifier was changed from uint8 to uint32
		ps.SessionID = bytes.ReadUint32(b[idx+offset:])
		idx += 4
	} else {
		ps.SessionID = uint32(b[idx+offset])
		idx++
	}

	// read env vars
	nvars := bytes.ReadUint16(b[idx+offset:])
	idx += 2
	var eoffset uint16
	for i := 0; i < int(nvars); i++ {
		klen := bytes.ReadUint16(b[idx+offset+uint32(eoffset):])
		buf = b[idx+2+offset+uint32(eoffset):]
		key := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:klen:klen])
		vlen := bytes.ReadUint16(b[idx+2+offset+uint32(eoffset)+uint32(klen):])
		buf = b[idx+4+offset+uint32(eoffset)+uint32(klen):]
		value := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:vlen:vlen])
		ps.Envs[key] = value
		eoffset += klen + vlen + 2 + 2
	}

	offset += uint32(eoffset)

	// read handles
	sec := section.Read(b[idx+offset:])
	offset += 10 // 10 is for the section size in bytes
	var hoffset uint32
	if sec.Len() == 0 {
		goto readpe
	}

	for i := 0; i < int(sec.Len()); i++ {
		// read handle length
		l := uint32(bytes.ReadUint16(b[idx+offset+hoffset:]))
		off := idx + 2 + hoffset + offset
		handle, err := htypes.NewFromCapture(b[off : off+l])
		if err != nil {
			return err
		}
		ps.Handles = append(ps.Handles, handle)
		hoffset += l + 2
	}

readpe:
	offset += hoffset
	// read PE metadata
	sec = section.Read(b[idx+offset:])
	idx += 10
	if sec.Size() == 0 {
		if psec.Version() >= capver.ProcessSecV2 {
			// read start time
			l := uint32(bytes.ReadUint16(b[idx+offset:]))
			idx += 2
			buf := b[idx+offset:]
			offset += l
			if len(buf) > 0 {
				var err error
				t := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])
				ps.StartTime, err = time.Parse(time.RFC3339Nano, t)
				if err != nil {
					return err
				}
			}
			// read UUID
			ps.uuid = bytes.ReadUint64(b[idx+offset:])
		}
		if psec.Version() >= capver.ProcessSecV3 {
			idx += 8
			// read username
			l := bytes.ReadUint16(b[idx+offset:])
			idx += 2
			buf := b[:]
			offset += uint32(l)
			ps.Username = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

			// read domain
			l = bytes.ReadUint16(b[idx+offset:])
			buf = b[:]
			idx += 2
			offset += uint32(l)
			ps.Domain = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])
		}
		if psec.Version() >= capver.ProcessSecV4 {
			// process flags
			ps.IsWOW64 = convert.Itob(b[idx+offset])
			idx++
			ps.IsPackaged = convert.Itob(b[idx+offset])
			idx++
			ps.IsProtected = convert.Itob(b[idx+offset])
		}

		return nil
	}

	var err error
	ps.PE, err = pe.NewFromCapture(b[idx+offset:], sec.Version())
	if err != nil {
		return err
	}

	offset += sec.Size()
	if psec.Version() >= capver.ProcessSecV2 {
		// read start time
		l := uint32(bytes.ReadUint16(b[idx+offset:]))
		idx += 2
		buf := b[idx+offset:]
		offset += l
		if len(buf) > 0 {
			ps.StartTime, _ = time.Parse(time.RFC3339Nano, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
		}
		// read UUID
		ps.uuid = bytes.ReadUint64(b[idx+offset:])
	}
	if psec.Version() >= capver.ProcessSecV3 {
		idx += 8
		// read username
		l := bytes.ReadUint16(b[idx+offset:])
		idx += 2
		buf := b[:]
		offset += uint32(l)
		ps.Username = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

		// read domain
		l = bytes.ReadUint16(b[idx+offset:])
		buf = b[:]
		idx += 2
		offset += uint32(l)
		ps.Domain = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])
	}
	if psec.Version() >= capver.ProcessSecV4 {
		// process flags
		ps.IsWOW64 = convert.Itob(b[idx+offset])
		idx++
		ps.IsPackaged = convert.Itob(b[idx+offset])
		idx++
		ps.IsProtected = convert.Itob(b[idx+offset])
	}

	return nil
}
