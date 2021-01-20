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
	"context"
	"crypto/md5"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"
)

// Sec contains the section attributes.
type Sec struct {
	Name    string
	Size    uint32
	Entropy float64
	Md5     string
}

// String returns the stirng representation of the section.
func (s Sec) String() string {
	return fmt.Sprintf("Name: %s, Size: %d, Entropy: %f, Md5: %s", s.Name, s.Size, s.Entropy, s.Md5)
}

func (r *reader) FindOffsetByRVA(rva uint32) (int64, error) {
	sec, err := r.FindSectionByRVA(rva)
	if err != nil {
		return 0, err
	}
	offset := int64(rva - r.fixSectionAlignment(sec.VirtualAddress) + r.fixFileAlignment(sec.Offset))
	return offset, nil
}

func (r *reader) FindSectionByRVA(rva uint32) (*pe.Section, error) {
	for _, s := range r.sections {
		if r.containsRVA(s, rva) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("couldn't find section at RVA 0x%x", rva)
}

func (r *reader) readSections(pefile *pe.File) []Sec {
	secs := pefile.Sections
	sections := make([]Sec, 0, len(secs))
	var wg sync.WaitGroup

	if r.config.ReadSections {
		wg.Add(len(secs))
	}
	for i := 0; i < len(secs); i++ {
		s := secs[i]
		if s == nil {
			continue
		}

		sec := Sec{
			Name: s.Name,
			Size: s.Size,
		}

		if r.config.ReadSections {
			ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*250)
			go func(wg *sync.WaitGroup, cancel context.CancelFunc) {
				defer cancel()
				data, err := s.Data()
				if err != nil {
					return
				}
				sum := md5.Sum(data)
				sec.Md5 = hex.EncodeToString(sum[:])
				//sec.Entropy = entropy(data)
				sections = append(sections, sec)
			}(&wg, cancel)

			<-ctx.Done()
			wg.Done()

		} else {
			sections = append(sections, sec)
		}

	}

	if r.config.ReadSections {
		wg.Wait()
	}

	return sections
}

// containsRVA determines whether the section contains the address provided by checking the boundaries
// of the section address intervals.
func (r *reader) containsRVA(sec *pe.Section, rva uint32) bool {
	va := r.fixSectionAlignment(sec.VirtualAddress)
	if va <= rva && rva < va+sec.Size {
		return true
	}
	return false
}

// fixSecAlignment ensures the alignment of the section is greater or equal to the file alignment.
func (r *reader) fixSectionAlignment(rva uint32) uint32 {
	var fa uint32
	var sa uint32
	switch hdr := r.oh.(type) {
	case *pe.OptionalHeader32:
		fa = hdr.FileAlignment
		sa = hdr.SectionAlignment
	case *pe.OptionalHeader64:
		fa = hdr.FileAlignment
		sa = hdr.SectionAlignment
	}
	if int(sa) < os.Getpagesize() {
		sa = fa
	}
	if sa > 0 && (rva%fa) != 0 {
		return sa * (rva / sa)
	}
	return rva
}

// fixFileAlignment adjusts section file alignment.
func (r *reader) fixFileAlignment(rva uint32) uint32 {
	var fa uint32
	switch hdr := r.oh.(type) {
	case *pe.OptionalHeader32:
		fa = hdr.FileAlignment
	case *pe.OptionalHeader64:
		fa = hdr.FileAlignment
	}
	if fa < 0x200 {
		return rva
	}
	return (rva / 0x200) * 0x200
}
