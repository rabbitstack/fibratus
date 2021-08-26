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
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kcap/section"
	kcapver "github.com/rabbitstack/fibratus/pkg/kcap/version"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
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
	b = append(b, bytes.WriteUint16(uint16(len(ps.Comm)))...)
	b = append(b, ps.Comm...)
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
	b = append(b, ps.SessionID)

	// write env vars block
	b = append(b, bytes.WriteUint16(uint16(len(ps.Envs)))...)
	for k, v := range ps.Envs {
		b = append(b, bytes.WriteUint16(uint16(len(k)))...)
		b = append(b, k...)
		b = append(b, bytes.WriteUint16(uint16(len(v)))...)
		b = append(b, v...)
	}

	// write handles
	sec := section.New(section.Handle, kcapver.HandleSecV1, uint32(len(ps.Handles)), 0)
	b = append(b, sec[:]...)
	for _, handle := range ps.Handles {
		buf := handle.Marshal()
		b = append(b, bytes.WriteUint16(handle.Offset())...)
		b = append(b, buf...)
	}

	// write the PE metadata
	if ps.PE != nil {
		buf := ps.PE.Marshal()
		sec := section.New(section.PE, kcapver.PESecV1, 0, uint32(len(buf)))
		b = append(b, sec[:]...)
		b = append(b, buf...)
	} else {
		sec := section.New(section.PE, kcapver.PESecV1, 0, 0)
		b = append(b, sec[:]...)
	}

	return b
}

// Unmarshal recovers the process' state from the capture file.
func (ps *PS) Unmarshal(b []byte) error {
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
	ps.Comm = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

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
	// read session ID
	ps.SessionID = b[20+offset]

	// read env vars
	nvars := bytes.ReadUint16(b[21+offset:])
	var eoffset uint16
	for i := 0; i < int(nvars); i++ {
		klen := bytes.ReadUint16(b[23+offset+uint32(eoffset):])
		buf = b[25+offset+uint32(eoffset):]
		key := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:klen:klen])
		vlen := bytes.ReadUint16(b[25+offset+uint32(eoffset)+uint32(klen):])
		buf = b[27+offset+uint32(eoffset)+uint32(klen):]
		value := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:vlen:vlen])
		ps.Envs[key] = value
		eoffset += klen + vlen + 2 + 2
	}

	offset += uint32(eoffset)

	// read handles
	sec := section.Read(b[23+offset:])
	offset += 10 // 10 is for the section size in bytes
	var hoffset uint32
	if sec.Len() == 0 {
		goto readpe
	}

	for i := 0; i < int(sec.Len()); i++ {
		// read handle length
		l := uint32(bytes.ReadUint16(b[23+offset+hoffset:]))

		off := 25 + hoffset + offset

		handle, err := htypes.NewFromKcap(b[off : off+l])
		if err != nil {
			return err
		}
		ps.Handles = append(ps.Handles, handle)
		hoffset += l + 2
	}

readpe:
	offset += hoffset
	// read PE metadata
	sec = section.Read(b[23+offset:])
	if sec.Size() == 0 {
		return nil
	}
	var err error
	ps.PE, err = pe.NewFromKcap(b[33+offset:])
	if err != nil {
		return err
	}

	return nil
}

// Marshal transforms the thread state to byte stream for persisting to capture files.
func (t *Thread) Marshal() []byte {
	b := make([]byte, 0)

	// write thread/process ID
	b = append(b, bytes.WriteUint32(t.Tid)...)
	b = append(b, bytes.WriteUint32(t.Pid)...)

	// write priority fields
	b = append(b, t.IOPrio)
	b = append(b, t.BasePrio)
	b = append(b, t.PagePrio)

	// write stack/kernel/entrypoint addresses
	b = append(b, bytes.WriteUint16(uint16(len(t.UstackBase)))...)
	b = append(b, t.UstackBase...)
	b = append(b, bytes.WriteUint16(uint16(len(t.UstackLimit)))...)
	b = append(b, t.UstackLimit...)
	b = append(b, bytes.WriteUint16(uint16(len(t.KstackBase)))...)
	b = append(b, t.KstackBase...)
	b = append(b, bytes.WriteUint16(uint16(len(t.KstackLimit)))...)
	b = append(b, t.KstackLimit...)
	b = append(b, bytes.WriteUint16(uint16(len(t.Entrypoint)))...)
	b = append(b, t.Entrypoint...)

	return b
}

// Marshal produces a module byte stream state suitable for writing to capture files.
func (m *Module) Marshal() []byte {
	b := make([]byte, 0)

	// write size and checksum
	b = append(b, bytes.WriteUint32(m.Size)...)
	b = append(b, bytes.WriteUint32(m.Checksum)...)

	// write image name
	b = append(b, bytes.WriteUint16(uint16(len(m.Name)))...)
	b = append(b, m.Name...)

	// write addresses
	b = append(b, bytes.WriteUint16(uint16(len(m.BaseAddress)))...)
	b = append(b, m.BaseAddress...)
	b = append(b, bytes.WriteUint16(uint16(len(m.DefaultBaseAddress)))...)
	b = append(b, m.DefaultBaseAddress...)

	return b
}

// Unmarshal restores thead state from the byte slice.
func (t *Thread) Unmarshal(b []byte) (uint16, error) {
	if len(b) < 11 {
		return 0, fmt.Errorf("expected at least 11 bytes but got %d", len(b))
	}

	// read tid and pid
	t.Tid = bytes.ReadUint32(b[0:])
	t.Pid = bytes.ReadUint32(b[4:])

	// read priorities
	t.IOPrio = b[8]
	t.BasePrio = b[9]
	t.PagePrio = b[10]

	// read user space stack base address
	l := bytes.ReadUint16(b[11:])
	buf := b[13:]
	offset := l
	t.UstackBase = kparams.Hex(string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))

	// read user space stack limit
	l = bytes.ReadUint16(b[13+offset:])
	buf = b[15+offset:]
	offset += l
	t.UstackLimit = kparams.Hex(string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))

	// read kernel space stack base address
	l = bytes.ReadUint16(b[15+offset:])
	buf = b[17+offset:]
	offset += l
	t.KstackBase = kparams.Hex(string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))

	// read kernel space stack limit
	l = bytes.ReadUint16(b[17+offset:])
	buf = b[19+offset:]
	offset += l
	t.KstackLimit = kparams.Hex(string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))

	// read entry point address
	l = bytes.ReadUint16(b[19+offset:])
	buf = b[21+offset:]
	offset += l
	t.Entrypoint = kparams.Hex(string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))

	return offset + 21, nil
}

// Unmarshal  reconstructs module state from the byte stream.
func (m *Module) Unmarshal(b []byte) (uint16, error) {
	if len(b) < 11 {
		return 0, fmt.Errorf("expected at least 11 bytes but got %d", len(b))
	}

	// read size
	m.Size = bytes.ReadUint32(b[0:])
	// read checksum
	m.Checksum = bytes.ReadUint32(b[4:])

	// read DLL full path
	length := bytes.ReadUint16(b[8:])
	buf := b[10:]
	offset := length
	m.Name = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:length:length])

	// read addresses
	length = bytes.ReadUint16(b[10+offset:])
	buf = b[12+offset:]
	offset += length
	m.BaseAddress = kparams.Hex(string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:length:length]))

	length = bytes.ReadUint16(b[12+offset:])
	buf = b[14+offset:]
	offset += length
	m.DefaultBaseAddress = kparams.Hex(string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:length:length]))

	return offset + 14, nil
}
