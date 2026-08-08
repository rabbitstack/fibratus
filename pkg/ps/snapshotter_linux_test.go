//go:build linux

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

	"github.com/rabbitstack/fibratus/pkg/event"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxSnapshotterFindPut(t *testing.T) {
	s := NewLinuxSnapshotter()
	ps := &pstypes.PS{PID: 100, Name: "bash", StartBootTime: 1234}
	s.Put(ps)

	ok, got := s.Find(100)
	require.True(t, ok)
	assert.Equal(t, "bash", got.Name)
	assert.Equal(t, uint32(1), s.Size())

	require.NoError(t, s.Write(&event.Event{PID: 200, PS: &pstypes.PS{PID: 200, Name: "sh"}}))
	assert.Equal(t, uint32(2), s.Size())

	require.NoError(t, s.Remove(&event.Event{PID: 100}))
	ok, _ = s.Find(100)
	assert.False(t, ok)
}
