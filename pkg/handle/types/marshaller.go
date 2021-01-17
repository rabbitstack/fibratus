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
	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	"unsafe"
)

// md is the type alias for the metadata type
type md uint8

const (
	alpcport md = iota + 1
	mutant
	file
	unknown
	none
)

// Offset returns the next offset from which to read the binary data.
func (h Handle) Offset() uint16 {
	offset := 8 + 8 + 4 + 2 + uint16(len(h.Type)) + 2 + uint16(len(h.Name)) + 1
	if h.MD != nil {
		switch h.MD.(type) {
		case *AlpcPortInfo:
			offset += 16
		case *MutantInfo:
			offset += 5
		case *FileInfo:
			offset++
		}
	}
	return offset
}

// Marshal dumps the state of the handle to byte slice that is suitable for serializing to kcap file.
func (h *Handle) Marshal() []byte {
	b := make([]byte, 0)

	// write handle id, object address and the pid that owns this handle
	b = append(b, bytes.WriteUint64(uint64(h.Num))...)
	b = append(b, bytes.WriteUint64(h.Object)...)
	b = append(b, bytes.WriteUint32(h.Pid)...)

	// write handle type and name
	b = append(b, bytes.WriteUint16(uint16(len(h.Type)))...)
	b = append(b, h.Type...)

	b = append(b, bytes.WriteUint16(uint16(len(h.Name)))...)
	b = append(b, h.Name...)

	// write handle metadata
	if h.MD != nil {
		switch meta := h.MD.(type) {
		case *AlpcPortInfo:
			b = append(b, byte(alpcport))
			b = append(b, bytes.WriteUint32(meta.Flags)...)
			b = append(b, bytes.WriteUint32(meta.Seqno)...)
			b = append(b, bytes.WriteUint64(uint64(meta.Context))...)
		case *MutantInfo:
			b = append(b, byte(mutant))
			b = append(b, bytes.WriteUint32(uint32(meta.Count))...)
			if meta.IsAbandoned {
				b = append(b, 1)
			} else {
				b = append(b, 0)
			}
		case *FileInfo:
			b = append(b, byte(file))
			if meta.IsDirectory {
				b = append(b, 1)
			} else {
				b = append(b, 0)
			}
		default:
			b = append(b, byte(unknown))
		}
	} else {
		b = append(b, byte(none))
	}

	return b
}

// Unmarshal transforms the byte slice back to handle structure.
func (h *Handle) Unmarshal(b []byte) error {
	if len(b) < 20 {
		return fmt.Errorf("expected at least 20 bytes but got %d bytes", len(b))
	}

	// read handle identifier
	h.Num = handle.Handle(bytes.ReadUint64(b[0:]))
	// read object address
	h.Object = bytes.ReadUint64(b[8:])
	// read pid
	h.Pid = bytes.ReadUint32(b[16:])

	// read handle type and name
	l := bytes.ReadUint16(b[20:])
	buf := b[22:]
	offset := l
	if len(buf) > 0 {
		h.Type = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])
	}

	l = bytes.ReadUint16(b[22+offset:])
	buf = b[24+offset:]
	offset += l
	if len(buf) > 0 {
		h.Name = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])
	}

	typ := md(b[24+offset])
	if typ == none {
		return nil
	}

	switch typ {
	case alpcport:
		alpcPort := &AlpcPortInfo{
			Flags:   bytes.ReadUint32(b[25+offset:]),
			Seqno:   bytes.ReadUint32(b[29+offset:]),
			Context: uintptr(bytes.ReadUint64(b[33+offset:])),
		}
		h.MD = alpcPort
	case mutant:
		mut := &MutantInfo{
			Count:       int32(bytes.ReadUint32(b[25+offset:])),
			IsAbandoned: utob(b[29+offset]),
		}
		h.MD = mut
	case file:
		f := &FileInfo{
			IsDirectory: utob(b[25+offset]),
		}
		h.MD = f
	}

	return nil
}

func utob(u uint8) bool { return u > 0 }
