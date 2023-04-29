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
func (s *SnapshotterMock) Write(kevt *kevent.Kevent) error {
	args := s.Called(kevt)
	return args.Error(0)
}

// Remove method
func (s *SnapshotterMock) Remove(kevt *kevent.Kevent) error {
	args := s.Called(kevt)
	return args.Error(0)
}

// Find method
func (s *SnapshotterMock) Find(pid uint32) (bool, *pstypes.PS) {
	args := s.Called(pid)
	return args.Bool(0), args.Get(1).(*pstypes.PS)
}

// FindAndPut method
func (s *SnapshotterMock) FindAndPut(pid uint32) *pstypes.PS {
	args := s.Called(pid)
	return args.Get(0).(*pstypes.PS)
}

// Put method
func (s *SnapshotterMock) Put(ps *pstypes.PS) {}

// Size method
func (s *SnapshotterMock) Size() uint32 { args := s.Called(); return uint32(args.Int(0)) }

// Close method
func (s *SnapshotterMock) Close() error { return nil }

// GetSnapshot method
func (s *SnapshotterMock) GetSnapshot() []*pstypes.PS {
	args := s.Called()
	return args.Get(0).([]*pstypes.PS)
}

// AddThread method
func (s *SnapshotterMock) AddThread(kevt *kevent.Kevent) error {
	args := s.Called(kevt)
	return args.Error(0)
}

// AddModule method
func (s *SnapshotterMock) AddModule(kevt *kevent.Kevent) error {
	args := s.Called(kevt)
	return args.Error(0)
}

// RemoveThread method
func (s *SnapshotterMock) RemoveThread(pid uint32, tid uint32) error {
	args := s.Called(pid, tid)
	return args.Error(0)
}

// RemoveModule method
func (s *SnapshotterMock) RemoveModule(pid uint32, mod string) error {
	args := s.Called(pid, mod)
	return args.Error(0)
}

// WriteFromKcap method
func (s *SnapshotterMock) WriteFromKcap(kevt *kevent.Kevent) error { return nil }
