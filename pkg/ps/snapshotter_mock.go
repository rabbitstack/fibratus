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

package ps

import (
	"github.com/rabbitstack/fibratus/pkg/kevent"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/mock"
)

// SnapshotterMock is the process snapshotter mock used in tests.
type SnapshotterMock struct {
	mock.Mock
}

// Write method
func (s *SnapshotterMock) Write(kevt *kevent.Kevent) error { return nil }

// Remove method
func (s *SnapshotterMock) Remove(kevt *kevent.Kevent) error { return nil }

// Find method
func (s *SnapshotterMock) Find(pid uint32) *pstypes.PS {
	args := s.Called(pid)
	return args.Get(0).(*pstypes.PS)
}

// Size method
func (s *SnapshotterMock) Size() uint32 { args := s.Called(); return uint32(args.Int(0)) }

// Close method
func (s *SnapshotterMock) Close() error { return nil }

// GetSnapshot method
func (s *SnapshotterMock) GetSnapshot() []*pstypes.PS {
	args := s.Called()
	return args.Get(0).([]*pstypes.PS)
}

// WriteFromKcap method
func (s *SnapshotterMock) WriteFromKcap(kevt *kevent.Kevent) error { return nil }
