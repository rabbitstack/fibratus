// +build windows

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
	"bytes"
	"debug/pe"
	"expvar"
	log "github.com/sirupsen/logrus"
	"golang.org/x/text/encoding/unicode"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	peSkippedImages  = expvar.NewInt("pe.skipped.images")
	peReaderTimeouts = expvar.NewInt("pe.reader.timeouts")
)

// Reader is the interface for PE (Portable Executable) format metadata parsing. The stdlib debug/pe package underpins
// the core functionality of the reader, but additionally, it provides numerous methods for reading resources, strings,
// IAT directories and other information that is not offered by the standard library package.
type Reader interface {
	// Read is the main method that reads the PE metadata for the specified image file.
	Read(filename string) (*PE, error)
	// FindSectionByRVA gets the section containing the given address.
	FindSectionByRVA(rva uint32) (*pe.Section, error)
	// FindOffsetByRVA returns the file offset that maps to the given RVA.
	FindOffsetByRVA(rva uint32) (int64, error)
}

type reader struct {
	f        *os.File
	sections []*pe.Section
	oh       interface{}
	config   Config
}

// NewReader builds a new instance of the PE reader.
func NewReader(config Config) Reader {
	return &reader{config: config}
}

func (r *reader) Read(filename string) (*PE, error) {
	if !r.config.Enabled {
		return nil, nil
	}
	if r.config.shouldSkipImage(filename) {
		peSkippedImages.Add(1)
		return nil, nil
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	r.f = f
	defer r.f.Close()
	pefile, err := pe.NewFile(f)
	if err != nil {
		return nil, err
	}
	r.sections = pefile.Sections
	r.oh = pefile.OptionalHeader

	// link time in PE header is represented as the number of seconds since January 1, 1970
	linkTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Second * time.Duration(pefile.TimeDateStamp))

	p := &PE{
		NumberOfSections: pefile.NumberOfSections,
		NumberOfSymbols:  pefile.NumberOfSymbols,
		LinkTime:         linkTime,
		Sections:         r.readSections(pefile),
		Symbols:          make([]string, 0),
		Imports:          make([]string, 0),
	}

	var resDir pe.DataDirectory
	switch hdr := r.oh.(type) {
	case *pe.OptionalHeader32:
		resDir = hdr.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
		p.ImageBase = uintToHex(uint64(hdr.ImageBase))
		p.EntryPoint = uintToHex(uint64(hdr.AddressOfEntryPoint))
	case *pe.OptionalHeader64:
		resDir = hdr.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
		p.ImageBase = uintToHex(hdr.ImageBase)
		p.EntryPoint = uintToHex(uint64(hdr.AddressOfEntryPoint))
	}

	var wg sync.WaitGroup

	if r.config.ReadResources {
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()
			p.VersionResources, err = r.readResources(resDir.VirtualAddress)
			if err != nil {
				log.Warnf("fail to read %q PE resources: %v", filename, err)
			}
		}(&wg)
	}

	if r.config.ReadSymbols {
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()
			symbols, err := pefile.ImportedSymbols()
			if err != nil {
				log.Warnf("fail to read %q symbols: %v", filename, err)
				return
			}
			// each symbol is anchored to its source library so we
			// can dig out the imports from the symbol name
			for _, sym := range symbols {
				fields := strings.SplitN(sym, ":", 2)
				if len(fields) != 2 {
					continue
				}
				symbol, lib := fields[0], fields[1]
				p.addImport(lib)
				p.addSymbol(symbol)
			}
		}(&wg)
	}

	// ensure this method terminates in a timely manner
	done := make(chan struct{})

	go func() {
		wg.Wait()
		done <- struct{}{}
	}()

	select {
	case <-done:
		return p, nil
	case <-time.After(time.Second):
		log.Warn("wait timeout reached during PE metadata parsing")
		peReaderTimeouts.Add(1)
		return p, nil
	}
}

// readUTF16String reads an UTF16 string at the specified RVA.
func (r *reader) readUTF16String(rva uint32) (string, error) {
	data := make([]byte, 1024)
	offset, err := r.FindOffsetByRVA(rva)
	if err != nil {
		return "", err
	}
	n, err := r.f.ReadAt(data, offset)
	if err != nil {
		if err == io.EOF {
			return "", nil
		}
		return "", err
	}
	idx := bytes.Index(data[:n], []byte{0, 0})
	if idx < 0 {
		idx = n - 1
	}
	decoder := unicode.UTF16(unicode.LittleEndian, unicode.UseBOM).NewDecoder()
	utf8, err := decoder.Bytes(data[0 : idx+1])
	if err != nil {
		return "", err
	}
	return string(utf8), nil
}

func dwordAlign(offset, base int64) int64 {
	return ((offset + base + 3) & 0xfffffffc) - (base & 0xfffffffc)
}

func uintToHex(v uint64) string { return strconv.FormatUint(v, 16) }
