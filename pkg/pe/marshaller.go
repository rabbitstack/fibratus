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

package pe

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	"math"
	"time"
	"unsafe"
)

// Marshal dumps the PE metadata to binary stream.
func (pe *PE) Marshal() []byte {
	b := make([]byte, 0)

	// number of sections/symbols
	b = append(b, bytes.WriteUint16(pe.NumberOfSections)...)
	b = append(b, bytes.WriteUint32(pe.NumberOfSymbols)...)

	// image base
	b = append(b, bytes.WriteUint16(uint16(len(pe.ImageBase)))...)
	b = append(b, pe.ImageBase...)

	// entry point
	b = append(b, bytes.WriteUint16(uint16(len(pe.EntryPoint)))...)
	b = append(b, pe.EntryPoint...)

	// link time
	linkTime := make([]byte, 0)
	linkTime = pe.LinkTime.AppendFormat(linkTime, time.RFC3339Nano)
	b = append(b, bytes.WriteUint16(uint16(len(linkTime)))...)
	b = append(b, linkTime...)

	// sections
	b = append(b, bytes.WriteUint16(uint16(len(pe.Sections)))...)
	for _, sec := range pe.Sections {
		// size
		b = append(b, bytes.WriteUint32(sec.Size)...)
		// entropy
		b = append(b, bytes.WriteUint64(math.Float64bits(sec.Entropy))...)
		// name
		b = append(b, bytes.WriteUint16(uint16(len(sec.Name)))...)
		b = append(b, sec.Name...)
		// md5
		b = append(b, bytes.WriteUint16(uint16(len(sec.Md5)))...)
		b = append(b, sec.Md5...)
	}

	// symbols
	b = append(b, bytes.WriteUint16(uint16(len(pe.Symbols)))...)
	for _, sym := range pe.Symbols {
		b = append(b, bytes.WriteUint16(uint16(len(sym)))...)
		b = append(b, sym...)
	}

	// imports
	b = append(b, bytes.WriteUint16(uint16(len(pe.Imports)))...)
	for _, imp := range pe.Imports {
		b = append(b, bytes.WriteUint16(uint16(len(imp)))...)
		b = append(b, imp...)
	}

	// version resources
	b = append(b, bytes.WriteUint16(uint16(len(pe.VersionResources)))...)
	for k, v := range pe.VersionResources {
		b = append(b, bytes.WriteUint16(uint16(len(k)))...)
		b = append(b, k...)
		b = append(b, bytes.WriteUint16(uint16(len(v)))...)
		b = append(b, v...)
	}

	return b
}

// Unmarshal recovers the PE metadata from the byte stream.
func (pe *PE) Unmarshal(b []byte) error {
	if len(b) < 6 {
		return fmt.Errorf("expected at least 6 bytes but got %d bytes", len(b))
	}

	pe.NumberOfSections = bytes.ReadUint16(b[0:])
	pe.NumberOfSymbols = bytes.ReadUint32(b[2:])

	// image base
	l := bytes.ReadUint16(b[6:])
	buf := b[8:]
	offset := uint32(l)
	pe.ImageBase = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// entry point
	l = bytes.ReadUint16(b[8+offset:])
	buf = b[10+offset:]
	offset += uint32(l)
	pe.EntryPoint = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// link time
	l = bytes.ReadUint16(b[10+offset:])
	buf = b[12+offset:]
	offset += uint32(l)
	if len(buf) > 0 {
		pe.LinkTime, _ = time.Parse(time.RFC3339Nano, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
	}

	// read sections
	nsections := bytes.ReadUint16(b[12+offset:])
	var soffset uint32

	for nsec := 0; nsec < int(nsections); nsec++ {
		// section size
		size := bytes.ReadUint32(b[14+offset+soffset:])
		// entropy
		entropy := bytes.ReadUint64(b[18+offset+soffset:])

		// section name
		l := bytes.ReadUint16(b[26+offset+soffset:])
		buf := b[28+offset+soffset:]
		soffset += uint32(l)
		name := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

		// section md5 hash
		l = bytes.ReadUint16(b[28+offset+soffset:])
		buf = b[30+offset+soffset:]
		soffset += uint32(l)
		md5 := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

		pe.Sections = append(pe.Sections,
			Sec{
				Name:    name,
				Size:    size,
				Entropy: math.Float64frombits(entropy),
				Md5:     md5,
			},
		)

		// increment the offset by summing the byte length of the size + entropy, and the section name length + md5 length encoded as uint16 values
		soffset += 4 + 8 + 2 + 2
	}

	offset += soffset

	// read symbols
	nsyms := bytes.ReadUint16(b[14+offset:])
	var syoffset uint32

	for nsym := 0; nsym < int(nsyms); nsym++ {
		l := bytes.ReadUint16(b[16+offset+syoffset:])
		buf := b[18+offset+syoffset:]
		pe.Symbols = append(pe.Symbols, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
		syoffset += uint32(l + 2)
	}
	offset += syoffset

	// read imports
	nimports := bytes.ReadUint16(b[16+offset:])
	var ioffset uint32

	for nimp := 0; nimp < int(nimports); nimp++ {
		l := bytes.ReadUint16(b[18+offset+ioffset:])
		buf := b[20+offset+ioffset:]
		pe.Imports = append(pe.Imports, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
		ioffset += uint32(l + 2)
	}

	offset += ioffset

	// read version resources
	nresources := bytes.ReadUint16(b[18+offset:])
	var roffset uint32

	for nres := 0; nres < int(nresources); nres++ {
		// read key
		klen := bytes.ReadUint16(b[20+offset+roffset:])
		buf := b[22+offset+roffset:]
		key := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:klen:klen])
		// read value
		vlen := bytes.ReadUint16(b[22+offset+uint32(klen)+roffset:])
		buf = b[24+offset+uint32(klen)+roffset:]
		if vlen == 0 {
			roffset += uint32(klen) + 4
			continue
		}
		value := string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:vlen:vlen])
		// increment the offset by the length of the key + length value + size of uint16 * 2
		// that corresponds to byte patterns storing the lengths of the keys/values
		roffset += uint32(klen) + uint32(vlen) + 4
		if key != "" {
			pe.VersionResources[key] = value
		}
	}

	return nil
}

// NewFromKcap restores the PE metadata from the byte stream.
func NewFromKcap(b []byte) (*PE, error) {
	pe := &PE{
		Sections:         make([]Sec, 0),
		Symbols:          make([]string, 0),
		Imports:          make([]string, 0),
		VersionResources: make(map[string]string),
	}
	if err := pe.Unmarshal(b); err != nil {
		return nil, err
	}
	return pe, nil
}
