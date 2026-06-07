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

package processors

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestFsProcessor(t *testing.T) {
	var tests = []struct {
		name           string
		e              *event.Event
		setupProcessor func(Processor)
		hsnap          func() *handle.SnapshotterMock
		assertions     func(*event.Event, *testing.T, *handle.SnapshotterMock, Processor)
	}{
		{
			"process file rundown",
			&event.Event{
				Type:     event.FileRundown,
				Category: event.File,
				Params: event.Params{
					params.FileObject: {Name: params.FileObject, Type: params.Uint64, Value: uint64(124567380264)},
					params.FilePath:   {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				fsProcessor := p.(*fsProcessor)
				assert.Contains(t, fsProcessor.files, uint64(124567380264))
				file := fsProcessor.files[124567380264]
				assert.Equal(t, "C:\\Windows\\system32\\user32.dll", file.Name)
				assert.Equal(t, fs.Regular, file.Type)
			},
		},
		{
			"process mapped file rundown",
			&event.Event{
				PID:      10233,
				Type:     event.MapFileRundown,
				Category: event.File,
				Params: event.Params{
					params.FileKey:             {Name: params.FileKey, Type: params.Uint64, Value: uint64(124567380264)},
					params.FileViewSize:        {Name: params.FileViewSize, Type: params.Uint64, Value: uint64(3098)},
					params.FileViewBase:        {Name: params.FileViewBase, Type: params.Uint64, Value: uint64(0xffff23433)},
					params.FileViewSectionType: {Name: params.FileViewSectionType, Type: params.Enum, Value: uint32(va.SectionImage), Enum: event.ViewSectionTypes},
				},
			},
			func(p Processor) {
				fsProcessor := p.(*fsProcessor)
				fsProcessor.files[124567380264] = &FileInfo{Name: "C:\\Windows\\System32\\kernel32.dll"}
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				fsProcessor := p.(*fsProcessor)

				assert.Equal(t, "C:\\Windows\\System32\\kernel32.dll", e.GetParamAsString(params.FilePath))

				psnap := fsProcessor.psnap.(*ps.SnapshotterMock)
				psnap.AssertNumberOfCalls(t, "AddMmap", 1)
			},
		},
		{
			"release file and remove file info",
			&event.Event{
				Type:     event.ReleaseFile,
				Category: event.File,
				Params: event.Params{
					params.FileObject: {Name: params.FileObject, Type: params.Uint64, Value: uint64(18446738026482168384)},
					params.FileKey:    {Name: params.FileKey, Type: params.Uint64, Value: uint64(14446538026482168384)},
				},
			},
			func(p Processor) {
				fsProcessor := p.(*fsProcessor)
				fsProcessor.files[18446738026482168384] = &FileInfo{Name: "C:\\Windows\\temp\\idxx.exe", Type: fs.Regular}
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				fsProcessor := p.(*fsProcessor)
				assert.Empty(t, fsProcessor.files)
			},
		},
		{
			"unmap view file",
			&event.Event{
				PID:      10233,
				Type:     event.UnmapViewFile,
				Category: event.File,
				Params: event.Params{
					params.FileKey:             {Name: params.FileKey, Type: params.Uint64, Value: uint64(124567380264)},
					params.FileViewSize:        {Name: params.FileViewSize, Type: params.Uint64, Value: uint64(3098)},
					params.FileViewBase:        {Name: params.FileViewBase, Type: params.Uint64, Value: uint64(0xffff23433)},
					params.FileViewSectionType: {Name: params.FileViewSectionType, Type: params.Enum, Value: uint32(va.SectionImage), Enum: event.ViewSectionTypes},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				fsProcessor := p.(*fsProcessor)

				psnap := fsProcessor.psnap.(*ps.SnapshotterMock)
				psnap.AssertNumberOfCalls(t, "RemoveMmap", 1)
			},
		},
		{
			"process write file",
			&event.Event{
				Type:     event.WriteFile,
				Category: event.File,
				Params: event.Params{
					params.FileObject: {Name: params.FileObject, Type: params.Uint64, Value: uint64(18446738026482168384)},
					params.FileKey:    {Name: params.FileKey, Type: params.Uint64, Value: uint64(14446538026482168384)},
					params.FileIoSize: {Name: params.FileIoSize, Type: params.Uint32, Value: uint32(1024)},
				},
			},
			func(p Processor) {
				fsProcessor := p.(*fsProcessor)
				fsProcessor.files[18446738026482168384] = &FileInfo{Name: "C:\\Windows\\temp\\idxx.exe", Type: fs.Regular}
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, event.WriteFile, e.Type)
				assert.Contains(t, e.Params, params.FilePath, params.FileType)
				assert.Equal(t, "C:\\Windows\\temp\\idxx.exe", e.GetParamAsString(params.FilePath))
				assert.Equal(t, "File", e.GetParamAsString(params.FileType))
			},
		},
		{
			"process write file consult handle snapshotter",
			&event.Event{
				Type:     event.WriteFile,
				Category: event.File,
				Params: event.Params{
					params.FileObject: {Name: params.FileObject, Type: params.Uint64, Value: uint64(18446738026482168384)},
					params.FileKey:    {Name: params.FileKey, Type: params.Uint64, Value: uint64(14446538026482168384)},
					params.FileIoSize: {Name: params.FileIoSize, Type: params.Uint32, Value: uint32(1024)},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				hsnap.On("FindByObject", uint64(18446738026482168384)).Return(htypes.Handle{Type: handle.File, Name: "C:\\Windows\\temp\\doc.docx"}, true)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, event.WriteFile, e.Type)
				hsnap.AssertNumberOfCalls(t, "FindByObject", 1)
				assert.Contains(t, e.Params, params.FilePath, params.FileType)
				assert.Equal(t, "C:\\Windows\\temp\\doc.docx", e.GetParamAsString(params.FilePath))
				assert.Equal(t, "File", e.GetParamAsString(params.FileType))
			},
		},
		{
			"process enum directory",
			&event.Event{
				Type:     event.EnumDirectory,
				Category: event.File,
				Params: event.Params{
					params.FileObject: {Name: params.FileObject, Type: params.Uint64, Value: uint64(18446738026482168384)},
					params.FileKey:    {Name: params.FileKey, Type: params.Uint64, Value: uint64(14446538026482168384)},
					params.FilePath:   {Name: params.FilePath, Type: params.UnicodeString, Value: "*"},
				},
			},
			func(p Processor) {
				fsProcessor := p.(*fsProcessor)
				fsProcessor.files[14446538026482168384] = &FileInfo{Name: "C:\\Windows\\temp", Type: fs.Regular}
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *event.Event, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, event.EnumDirectory, e.Type)
				assert.Contains(t, e.Params, params.FilePath, params.FileDirectory)
				assert.Equal(t, "C:\\Windows\\temp", e.GetParamAsString(params.FileDirectory))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hsnap := tt.hsnap()
			psnap := new(ps.SnapshotterMock)
			psnap.On("AddMmap", mock.Anything).Return(nil)
			psnap.On("RemoveMmap", mock.Anything, mock.Anything).Return(nil)
			psnap.On("Find", mock.Anything).Return(true, &pstypes.PS{
				Mmaps: []pstypes.Mmap{
					{File: "C:\\Windows\\System32\\kernel32.dll", BaseAddress: va.Address(0xffff23433), Size: 3098},
				},
			})
			p := newFsProcessor(hsnap, psnap, &config.Config{})
			if tt.setupProcessor != nil {
				tt.setupProcessor(p)
			}
			var err error
			tt.e, _, err = p.ProcessEvent(tt.e)
			require.NoError(t, err)
			tt.assertions(tt.e, t, hsnap, p)
		})
	}
}
