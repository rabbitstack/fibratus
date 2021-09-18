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

package types

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"strings"
)

// Meta represents the type alias for handle meta information
type Meta interface{}

// Handles represents a collection of handles.
type Handles []Handle

// Handle stores various metadata specific to the handle allocated by a process.
type Handle struct {
	// Num represents the internal handle identifier.
	Num handle.Handle `json:"id"`
	// Object is the kernel address that this handle references.
	Object uint64 `json:"-"`
	// Pid represents the process's identifier that owns the handle.
	Pid uint32 `json:"-"`
	// Type is the type of this handle (e.g. File, Key, Mutant, Section)
	Type string `json:"type"`
	// Name is the actual value of the handle (e.g. \Device\HarddiskVolume4\Windows\Temp\DPTF)
	Name string `json:"name"`
	// MD is the handle meta information (e.g. ALPC port info)
	MD Meta `json:"meta,omitempty"`
}

// String returns a string representation of the handle.
func (h Handle) String() string {
	return fmt.Sprintf("Num: %d Type: %s, Name: %s, Object: 0x%x, PID: %d", h.Num, h.Type, h.Name, h.Object, h.Pid)
}

// Len returns the length in bytes of the Handle structure.
func (h Handle) Len() int {
	l := 8 + 8 + 4 + len(h.Type) + len(h.Name)
	if h.MD != nil {
		switch h.MD.(type) {
		case *AlpcPortInfo:
			l += 16
		case *MutantInfo:
			l += 5
		case *FileInfo:
			l++
		}
	}
	return l
}

// NewFromKcap restores handle state from the kcap buffer.
func NewFromKcap(buf []byte) (Handle, error) {
	h := Handle{}
	err := h.Unmarshal(buf)
	if err != nil {
		return Handle{}, err
	}
	return h, nil
}

// AlpcPortInfo stores ALPC port basic information.
type AlpcPortInfo struct {
	Flags   uint32
	Seqno   uint32
	Context uintptr
}

// MutantInfo stores metadata about particular mutant object.
type MutantInfo struct {
	Count       int32
	IsAbandoned bool
}

// FileInfo contains file handle metadata.
type FileInfo struct {
	IsDirectory bool
}

// String returns the string representation of all handles.
func (handles Handles) String() string {
	var sb strings.Builder
	for _, h := range handles {
		sb.WriteString(h.String() + " | ")
	}
	return strings.TrimSuffix(sb.String(), " | ")
}
