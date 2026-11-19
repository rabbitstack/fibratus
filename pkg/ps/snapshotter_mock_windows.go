//go:build windows

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
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/mock"
)

// SnapshotterMock is the process snapshotter mock used in tests.
type SnapshotterMock struct {
	mock.Mock
}

// AddProcess method
func (s *SnapshotterMock) AddProcess(proc *pstypes.PS) error {
	args := s.Called(proc)
	return args.Error(0)
}

// RemoveProcess method
func (s *SnapshotterMock) RemoveProcess(pid uint32) {
	s.Called(pid)
}

// Find method
func (s *SnapshotterMock) Find(pid uint32) (*pstypes.PS, bool) {
	args := s.Called(pid)
	return args.Get(0).(*pstypes.PS), args.Bool(1)
}

func (s *SnapshotterMock) FindModule(addr va.Address) (*pstypes.Module, bool) {
	args := s.Called(addr)
	mod := args.Get(0)
	if mod != nil {
		return mod.(*pstypes.Module), args.Bool(1)
	}
	return nil, args.Bool(1)
}

func (s *SnapshotterMock) FindAllModules() map[string]pstypes.Module {
	args := s.Called()
	return args.Get(0).(map[string]pstypes.Module)
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
func (s *SnapshotterMock) AddThread(thread pstypes.Thread) {
	s.Called(thread)
}

// AddModule method
func (s *SnapshotterMock) AddModule(pid uint32, mod pstypes.Module) {
	s.Called(pid, mod)
}

// RemoveThread method
func (s *SnapshotterMock) RemoveThread(pid uint32, tid uint32) {
	s.Called(pid, tid)
}

// RemoveModule method
func (s *SnapshotterMock) RemoveModule(pid uint32, addr va.Address) {
	s.Called(pid, addr)
}

// AddMmap method
func (s *SnapshotterMock) AddMmap(pid uint32, mmap pstypes.Mmap) {
	s.Called(pid, mmap)
}

// RemoveMmap method
func (s *SnapshotterMock) RemoveMmap(pid uint32, address va.Address) {
	s.Called(pid, address)
}
