//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

package ps

import (
	"testing"

	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSnapshotterFindPut(t *testing.T) {
	s := NewSnapshotter()
	ps := &pstypes.PS{PID: 100, Name: "bash", StartBootTime: 1234}
	s.Put(ps)

	ok, got := s.Find(100)
	require.True(t, ok)
	assert.Equal(t, "bash", got.Name)
	assert.Equal(t, uint32(1), s.Size())

	require.NoError(t, s.AddProcess(&pstypes.PS{PID: 200, Name: "sh"}))
	assert.Equal(t, uint32(2), s.Size())

	require.NoError(t, s.RemoveProcess(100))
	ok, _ = s.Find(100)
	assert.False(t, ok)
}

func TestSnapshotterAddRemoveThread(t *testing.T) {
	s := NewSnapshotter()
	s.Put(&pstypes.PS{PID: 100, Name: "bash", Threads: make(map[uint32]pstypes.Thread)})

	require.NoError(t, s.AddThread(pstypes.Thread{Pid: 100, Tid: 101}))
	_, ps := s.Find(100)
	assert.Contains(t, ps.Threads, uint32(101))

	// threads of unknown processes are ignored
	require.NoError(t, s.AddThread(pstypes.Thread{Pid: 999, Tid: 1}))
	assert.Equal(t, uint32(1), s.Size())

	require.NoError(t, s.RemoveThread(100, 101))
	assert.NotContains(t, ps.Threads, uint32(101))
}

func TestSnapshotterAddRemoveMmap(t *testing.T) {
	s := NewSnapshotter()
	s.Put(&pstypes.PS{PID: 100, Name: "bash"})

	require.NoError(t, s.AddMmap(100, pstypes.Mmap{BaseAddress: 0x7000, Size: 4096}))
	_, ps := s.Find(100)
	assert.Len(t, ps.Mmaps, 1)

	require.NoError(t, s.AddMmap(999, pstypes.Mmap{BaseAddress: 0x8000}))
	assert.Len(t, ps.Mmaps, 1)

	require.NoError(t, s.RemoveMmap(100, 0x7000))
	assert.Len(t, ps.Mmaps, 0)
}
