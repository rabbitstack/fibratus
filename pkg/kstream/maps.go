//go:build linux
// +build linux

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

package kstream

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
)

// MapType is the type alias for possible map types in the eBPF program
type MapType uint16

const (
	// Perf map is an array whose size is the number of available CPUs,
	// and each cell contains a value relative to one CPU.
	// The value to retrieve is indicated by flags, that
	// contains the index of the CPU to look up, masked
	// with BPF_F_INDEX_MASK.
	Perf MapType = iota
	// Tracers is the BPF_MAP_TYPE_PROG_ARRAY map type where the key is
	// the event type identifier and the value represents the file
	// descriptor of the eBPF program for the tail call
	Tracers
	// Discarders is the BPF_MAP_TYPE_LRU_HASH map type that stores
	// discriminants used to drop the event in kernel space.
	Discarders
	KparSpecs
)

// maxKpars represents the maximum number of parameters in the kevent
const maxKpars = 1 << 5

// maxKparName is the max size of the parameter name
const maxKparName = 32

var ebpfMaps = [...]string{
	"perf",
	"tracers",
	"discarders",
	"kparspecs",
}

type DiscarderKey struct {
	Comm [16]byte
}

type KparSpec struct {
	Name [maxKparName]byte
	Type uint16
}

type KparsValue struct {
	Nparams uint32
	Kpars   [maxKpars]KparSpec
}

func (d *DiscarderKey) MarshalBinary() ([]byte, error) {
	return d.Comm[:], nil
}

func (d *DiscarderKey) UnmarshalBinary(buf []byte) error {
	copy(d.Comm[:], buf)
	return nil
}

func (k KparsValue) MarshalBinary() ([]byte, error) {
	b := make([]byte, 4+((2+maxKparName)*maxKpars))
	binary.LittleEndian.PutUint32(b, k.Nparams)
	offset := 0
	for i := range k.Kpars {
		copy(b[4+offset:], k.Kpars[i].Name[:])
		binary.LittleEndian.PutUint16(b[4+maxKparName+offset:], k.Kpars[i].Type)
		offset += 2
	}
	return b, nil
}

func (m MapType) String() string {
	switch m {
	case Perf:
		return "perf"
	case Tracers:
		return "tracers"
	case Discarders:
		return "discarders"
	case KparSpecs:
		return "kparspecs"
	}
	return ""
}

// Maps represents the type alias that stores well-known ebpf maps
type Maps map[string]*ebpf.Map

// ToMaps converts the raw to aliased map type and
// checks the presence of the mandatory map definitions.
func ToMaps(maps map[string]*ebpf.Map) (Maps, error) {
	for _, mapName := range ebpfMaps {
		if _, ok := maps[mapName]; !ok {
			return nil, fmt.Errorf("missing map %s", mapName)
		}
	}
	return Maps(maps), nil
}

func (maps Maps) GetMap(m MapType) *ebpf.Map {
	return maps[m.String()]
}

func (maps Maps) Put(m MapType, key, value interface{}) error {
	return maps[m.String()].Put(key, value)
}

func NewDiscarderKey(proc string) *DiscarderKey {
	var comm [16]byte
	copy(comm[:], proc)
	return &DiscarderKey{comm}
}

func NewKparsValue(kpars []ktypes.KparInfo) *KparsValue {
	kparsValue := &KparsValue{
		Nparams: uint32(len(kpars)),
	}
	for i, kpar := range kpars {
		var kparName [maxKparName]byte
		copy(kparName[:], kpar.Name)
		kparsValue.Kpars[i] = KparSpec{Name: kparName, Type: uint16(kpar.Type)}
	}
	return kparsValue
}
