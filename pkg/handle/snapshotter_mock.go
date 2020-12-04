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

package handle

import (
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/stretchr/testify/mock"
)

// SnapshotterMock is the mock handle snapshotter used in tests.
type SnapshotterMock struct {
	mock.Mock
}

// Write method
func (s *SnapshotterMock) Write(kevt *kevent.Kevent) error { return nil }

// Remove method
func (s *SnapshotterMock) Remove(kevt *kevent.Kevent) error { return nil }

// FindHandles method
func (s *SnapshotterMock) FindHandles(pid uint32) ([]htypes.Handle, error) { return nil, nil }

// FindByObject method
func (s *SnapshotterMock) FindByObject(object uint64) (htypes.Handle, bool) {
	return htypes.Handle{}, false
}

// RegisterCreateCallback method
func (s *SnapshotterMock) RegisterCreateCallback(fn CreateCallback) {}

// RegisterDestroyCallback method
func (s *SnapshotterMock) RegisterDestroyCallback(fn DestroyCallback) {}

// GetSnapshot method
func (s *SnapshotterMock) GetSnapshot() []htypes.Handle {
	handles := s.Called()
	return handles.Get(0).([]htypes.Handle)
}
