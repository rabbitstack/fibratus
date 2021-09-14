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
	"fmt"

	"github.com/cilium/ebpf"
)

type MapType uint16

const (
	// Perf map is an array whose size is the number of available CPUs,
	// and each cell contains a value relative to one CPU.
	// The value to retrieve is indicated by flags, that
	// contains the index of the CPU to look up, masked
	// with BPF_F_INDEX_MASK.
	Perf MapType = iota
	Tracers
	Discarders
)

var ebpfMaps = [...]string{
	"perf",
	"tracers",
	"discarders",
}

type DiscarderKey struct {
	Comm [16]byte
}

func (d *DiscarderKey) MarshalBinary() ([]byte, error) {
	return d.Comm[:], nil
}

func (d *DiscarderKey) UnmarshalBinary(buf []byte) error {
	copy(d.Comm[:], buf)
	return nil
}

func (m MapType) String() string {
	switch m {
	case Perf:
		return "perf"
	case Tracers:
		return "tracers"
	case Discarders:
		return "discarders"
	}
	return ""
}

type Maps map[string]*ebpf.Map

func (maps Maps) VerifyMaps() error {
	for _, mapName := range ebpfMaps {
		if _, ok := maps[mapName]; !ok {
			return fmt.Errorf("missing map %s", mapName)
		}
	}
	return nil
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
