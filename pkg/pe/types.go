//go:build windows
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
	"fmt"
	"time"
)

const (
	// Company represents the company name string file info entry in the resources table
	Company = "CompanyName"
	// FileDescription represents the file description entry in the resources table
	FileDescription = "FileDescription"
	// FileVersion represents the file version entry in the resources table
	FileVersion = "FileVersion"
	// OriginalFilename the name of the original executable in the resources table
	OriginalFilename = "OriginalFilename"
	// LegalCopyright represents the copyright notice in the resources directory table
	LegalCopyright = "LegalCopyright"
	// ProductName is the product name entry in the resources table
	ProductName = "ProductName"
	// ProductVersion is the product version entry in the resources table
	ProductVersion = "ProductVersion"
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

// PE contains various headers that identifies the format and characteristics of the executable files.
type PE struct {
	// NumberOfSections designates the total number of sections found withing the binary.
	NumberOfSections uint16 `json:"nsections"`
	// NumberOfSymbols represents the total number of symbols.
	NumberOfSymbols uint32 `json:"nsymbols"`
	// ImageBase designates the base address of the process' image.
	ImageBase string `json:"image_base"`
	// Entrypoint is the address of the entry point function.
	EntryPoint string `json:"entry_point"`
	// LinkTime represents the time that the image was created by the linker.
	LinkTime time.Time `json:"link_time"`
	// Sections contains all distinct sections and their metadata.
	Sections []Sec `json:"sections"`
	// Symbols contains the list of imported symbols.
	Symbols []string `json:"symbols"`
	// Imports contains the imported libraries.
	Imports []string `json:"imports"`
	// VersionResources holds the version resources
	VersionResources map[string]string `json:"resources"`
}

// String returns the string representation of the PE metadata.
func (pe PE) String() string {
	return fmt.Sprintf(`
		 Number of sections: %d
		 Number of symbols: %d
		 Image base: %s
		 Entrypoint: %s
		 Link time: %v
		 Sections: %v
		 Symbols: %v
		 Imports: %v
         Version resources: %v
		`,
		pe.NumberOfSections,
		pe.NumberOfSymbols,
		pe.ImageBase,
		pe.EntryPoint,
		pe.LinkTime,
		pe.Sections,
		pe.Symbols,
		pe.Imports,
		pe.VersionResources,
	)
}

// Section returns the section with specified name.
func (pe *PE) Section(s string) *Sec {
	for _, sec := range pe.Sections {
		if sec.Name == s {
			return &sec
		}
	}
	return nil
}

func (pe *PE) addImport(i string) {
	pe.Imports = append(pe.Imports, i)
}

func (pe *PE) addSymbol(s string) {
	pe.Symbols = append(pe.Symbols, s)
}
