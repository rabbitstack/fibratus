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

package ktypes

import (
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestEventsetMasks(t *testing.T) {
	var masks EventsetMasks
	masks.Set(TerminateThread)
	masks.Set(CreateThread)
	masks.Set(TerminateProcess)

	require.True(t, masks.Test(ThreadEventGUID, TerminateThread.HookID()))
	require.True(t, masks.Test(ThreadEventGUID, CreateThread.HookID()))
	require.False(t, masks.Test(ThreadEventGUID, ThreadRundown.HookID()))
	require.True(t, masks.Test(ProcessEventGUID, TerminateProcess.HookID()))
	require.False(t, masks.Test(ProcessEventGUID, CreateProcess.HookID()))

	masks.Clear(ThreadEventGUID)

	require.False(t, masks.Test(ThreadEventGUID, TerminateThread.HookID()))
	require.False(t, masks.Test(ThreadEventGUID, CreateThread.HookID()))
}

func BenchmarkEventsetMasks(b *testing.B) {
	b.ReportAllocs()

	var masks EventsetMasks
	masks.Set(TerminateThread)
	masks.Set(CreateThread)
	masks.Set(TerminateProcess)
	masks.Set(CreateFile)

	evt := etw.EventRecord{Header: etw.EventHeader{ProviderID: ThreadEventGUID, EventDescriptor: etw.EventDescriptor{Opcode: 2}}}

	for i := 0; i < b.N; i++ {
		if !masks.Test(evt.Header.ProviderID, uint16(evt.Header.EventDescriptor.Opcode)) {
			panic("mask should be present")
		}
	}
}

func BenchmarkStdlibMap(b *testing.B) {
	b.ReportAllocs()

	evts := make(map[Ktype]bool)
	evts[TerminateThread] = true
	evts[CreateThread] = true
	evts[TerminateProcess] = true
	evts[CreateFile] = true

	evt := etw.EventRecord{Header: etw.EventHeader{ProviderID: ThreadEventGUID, EventDescriptor: etw.EventDescriptor{Opcode: 2}}}
	kt := NewFromEventRecord(&evt)

	for i := 0; i < b.N; i++ {
		if !evts[kt] {
			panic("event should be present")
		}
	}
}
