/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package event

import (
	"github.com/rabbitstack/fibratus/pkg/util/bitmask"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/stretchr/testify/assert"
)

func TestBitmask(t *testing.T) {
	var tests = []struct {
		typ      Type
		expected bool
	}{
		{TerminateThread, true},
		{TerminateProcess, true},
		{CreateThread, true},
		{CreateFile, false},
		{WriteFile, false},
		{LoadImage, false},
		{MapFileRundown, true},
		{ProcessRundown, true},
	}

	b := bitmask.New()
	for _, typ := range AllWithState() {
		if typ == WriteFile || typ == LoadImage || typ == CreateFile {
			continue
		}
		b.Set(typ.ID())
	}

	for _, tt := range tests {
		t.Run(tt.typ.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, b.IsSet(tt.typ.ID()))
		})
	}
}

func TestBitSets(t *testing.T) {
	var tests = []struct {
		evt      *Event
		expected bool
	}{
		{&Event{Type: TerminateThread}, true},
		{&Event{Type: TerminateProcess}, true},
		{&Event{Type: CreateThread, Category: Thread}, true},
		{&Event{Type: CreateFile}, false},
		{&Event{Type: WriteFile}, false},
		{&Event{Type: LoadImage}, false},
		{&Event{Type: MapFileRundown}, true},
		{&Event{Type: ProcessRundown}, true},
	}

	var bitsets BitSets

	bitsets.SetBit(BitmaskBitSet, TerminateThread)
	bitsets.SetBit(TypeBitSet, TerminateProcess)
	bitsets.SetBit(CategoryBitSet, CreateThread)
	bitsets.SetBit(TypeBitSet, MapFileRundown)
	bitsets.SetBit(BitmaskBitSet, ProcessRundown)

	for _, tt := range tests {
		t.Run(tt.evt.Type.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, bitsets.IsBitSet(tt.evt))
		})
	}
}

func BenchmarkBitmask(b *testing.B) {
	b.ReportAllocs()

	bm := bitmask.New()
	bm.Set(TerminateThread.ID())
	bm.Set(CreateThread.ID())
	bm.Set(TerminateProcess.ID())
	bm.Set(CreateFile.ID())

	evt := &etw.EventRecord{Header: etw.EventHeader{ProviderID: ThreadEventGUID, EventDescriptor: etw.EventDescriptor{Opcode: 2}}}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !bm.IsSet(evt.ID()) {
			panic("mask should be present")
		}
	}
}

func BenchmarkStdlibMap(b *testing.B) {
	b.ReportAllocs()

	evts := make(map[Type]bool)
	evts[TerminateThread] = true
	evts[CreateThread] = true
	evts[TerminateProcess] = true
	evts[CreateFile] = true

	evt := etw.EventRecord{Header: etw.EventHeader{ProviderID: ThreadEventGUID, EventDescriptor: etw.EventDescriptor{Opcode: 2}}}
	etype := NewTypeFromEventRecord(&evt)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if !evts[etype] {
			panic("event should be present")
		}
	}
}
