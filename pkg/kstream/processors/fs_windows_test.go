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
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"reflect"
	"testing"
)

func TestFsProcessor(t *testing.T) {
	var tests = []struct {
		name           string
		e              *kevent.Kevent
		setupProcessor func(Processor)
		hsnap          func() *handle.SnapshotterMock
		assertions     func(*kevent.Kevent, *testing.T, *handle.SnapshotterMock, Processor)
	}{
		{
			"process file rundown",
			&kevent.Kevent{
				Type:     ktypes.FileRundown,
				Category: ktypes.File,
				Kparams: kevent.Kparams{
					kparams.FileObject: {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(124567380264)},
					kparams.FileName:   {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\user32.dll"},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				fsProcessor := p.(*fsProcessor)
				assert.Contains(t, fsProcessor.files, uint64(124567380264))
				file := fsProcessor.files[124567380264]
				assert.Equal(t, "C:\\Windows\\system32\\user32.dll", file.Name)
				assert.Equal(t, fs.Regular, file.Type)
			},
		},
		{
			"process mapped file rundown",
			&kevent.Kevent{
				PID:      10233,
				Type:     ktypes.MapFileRundown,
				Category: ktypes.File,
				Kparams: kevent.Kparams{
					kparams.FileKey:             {Name: kparams.FileKey, Type: kparams.Uint64, Value: uint64(124567380264)},
					kparams.FileViewSize:        {Name: kparams.FileViewSize, Type: kparams.Uint64, Value: uint64(3098)},
					kparams.FileViewBase:        {Name: kparams.FileViewBase, Type: kparams.Uint64, Value: uint64(0xffff23433)},
					kparams.FileViewSectionType: {Name: kparams.FileViewSectionType, Type: kparams.Enum, Value: uint32(va.SectionImage), Enum: kevent.ViewSectionTypes},
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
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				fsProcessor := p.(*fsProcessor)
				assert.Contains(t, fsProcessor.mmaps, uint32(10233))
				mapinfo := fsProcessor.mmaps[10233][124567380264]
				require.NotNil(t, mapinfo)
				assert.Equal(t, "C:\\Windows\\System32\\kernel32.dll", mapinfo.File)
				assert.Equal(t, uint64(3098), mapinfo.Size)
				assert.Equal(t, uint64(0xffff23433), mapinfo.BaseAddr)
			},
		},
		{
			"wait enqueue for create file events",
			&kevent.Kevent{
				Type:     ktypes.CreateFile,
				Category: ktypes.File,
				Kparams: kevent.Kparams{
					kparams.FileObject:        {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(18446738026482168384)},
					kparams.ThreadID:          {Name: kparams.ThreadID, Type: kparams.Uint32, Value: uint32(1484)},
					kparams.FileCreateOptions: {Name: kparams.FileCreateOptions, Type: kparams.Uint32, Value: uint32(1223456)},
					kparams.FileName:          {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\kernel32.dll"},
					kparams.FileShareMask:     {Name: kparams.FileShareMask, Type: kparams.Uint32, Value: uint32(5)},
					kparams.FileIrpPtr:        {Name: kparams.FileIrpPtr, Type: kparams.Uint64, Value: uint64(1234543123112321)},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				fsProcessor := p.(*fsProcessor)
				assert.True(t, e.WaitEnqueue)
				assert.Contains(t, fsProcessor.irps, uint64(1234543123112321))
				assert.True(t, reflect.DeepEqual(e, fsProcessor.irps[1234543123112321]))
			},
		},
		{
			"get IRP completion for create file event",
			&kevent.Kevent{
				Type:     ktypes.FileOpEnd,
				Category: ktypes.File,
				Kparams: kevent.Kparams{
					kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(18446738026482168384)},
					kparams.FileExtraInfo: {Name: kparams.FileExtraInfo, Type: kparams.Uint64, Value: uint64(2)},
					kparams.FileIrpPtr:    {Name: kparams.FileIrpPtr, Type: kparams.Uint64, Value: uint64(1334543123112321)},
					kparams.NTStatus:      {Name: kparams.NTStatus, Type: kparams.Status, Value: uint32(0)},
				},
			},
			func(p Processor) {
				fsProcessor := p.(*fsProcessor)
				fsProcessor.irps[1334543123112321] = &kevent.Kevent{
					Type:     ktypes.CreateFile,
					Category: ktypes.File,
					Kparams: kevent.Kparams{
						kparams.FileObject:        {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(12446738026482168384)},
						kparams.FileCreateOptions: {Name: kparams.FileCreateOptions, Type: kparams.Uint32, Value: uint32(18874368)},
						kparams.FileName:          {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\temp\\idxx.exe"},
						kparams.FileShareMask:     {Name: kparams.FileShareMask, Type: kparams.Uint32, Value: uint32(5)},
						kparams.FileIrpPtr:        {Name: kparams.FileIrpPtr, Type: kparams.Uint64, Value: uint64(1334543123112321)},
					},
				}
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				fsProcessor := p.(*fsProcessor)
				assert.Equal(t, ktypes.CreateFile, e.Type)
				assert.NotContains(t, fsProcessor.irps, uint64(1334543123112321))
				assert.False(t, e.WaitEnqueue)
				assert.Contains(t, fsProcessor.files, uint64(12446738026482168384))
				assert.Equal(t, "C:\\Windows\\temp\\idxx.exe", fsProcessor.files[12446738026482168384].Name)
				assert.Equal(t, "Success", e.GetParamAsString(kparams.NTStatus))
				assert.Equal(t, "File", e.GetParamAsString(kparams.FileType))
				assert.Equal(t, "CREATE", e.GetParamAsString(kparams.FileOperation))
			},
		},
		{
			"release file and remove file info",
			&kevent.Kevent{
				Type:     ktypes.ReleaseFile,
				Category: ktypes.File,
				Kparams: kevent.Kparams{
					kparams.FileObject: {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(18446738026482168384)},
					kparams.FileKey:    {Name: kparams.FileKey, Type: kparams.Uint64, Value: uint64(14446538026482168384)},
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
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				fsProcessor := p.(*fsProcessor)
				assert.Empty(t, fsProcessor.files)
			},
		},
		{
			"unmap view file",
			&kevent.Kevent{
				PID:      10233,
				Type:     ktypes.UnmapViewFile,
				Category: ktypes.File,
				Kparams: kevent.Kparams{
					kparams.FileKey:             {Name: kparams.FileKey, Type: kparams.Uint64, Value: uint64(124567380264)},
					kparams.FileViewSize:        {Name: kparams.FileViewSize, Type: kparams.Uint64, Value: uint64(3098)},
					kparams.FileViewBase:        {Name: kparams.FileViewBase, Type: kparams.Uint64, Value: uint64(0xffff23433)},
					kparams.FileViewSectionType: {Name: kparams.FileViewSectionType, Type: kparams.Enum, Value: uint32(va.SectionImage), Enum: kevent.ViewSectionTypes},
				},
			},
			func(p Processor) {
				fsProcessor := p.(*fsProcessor)
				fsProcessor.mmaps[10233] = make(map[uint64]*MmapInfo)
				fsProcessor.mmaps[10233][124567380264] = &MmapInfo{File: "C:\\Windows\\System32\\kernel32.dll"}
			},
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				fsProcessor := p.(*fsProcessor)
				assert.True(t, e.Kparams.Contains(kparams.FileName))
				assert.Nil(t, fsProcessor.mmaps[3098][124567380264])
			},
		},
		{
			"process write file",
			&kevent.Kevent{
				Type:     ktypes.WriteFile,
				Category: ktypes.File,
				Kparams: kevent.Kparams{
					kparams.FileObject: {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(18446738026482168384)},
					kparams.FileKey:    {Name: kparams.FileKey, Type: kparams.Uint64, Value: uint64(14446538026482168384)},
					kparams.FileIoSize: {Name: kparams.FileIoSize, Type: kparams.Uint32, Value: uint32(1024)},
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
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, ktypes.WriteFile, e.Type)
				assert.Contains(t, e.Kparams, kparams.FileName, kparams.FileType)
				assert.Equal(t, "C:\\Windows\\temp\\idxx.exe", e.GetParamAsString(kparams.FileName))
				assert.Equal(t, "File", e.GetParamAsString(kparams.FileType))
			},
		},
		{
			"process write file consult handle snapshotter",
			&kevent.Kevent{
				Type:     ktypes.WriteFile,
				Category: ktypes.File,
				Kparams: kevent.Kparams{
					kparams.FileObject: {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(18446738026482168384)},
					kparams.FileKey:    {Name: kparams.FileKey, Type: kparams.Uint64, Value: uint64(14446538026482168384)},
					kparams.FileIoSize: {Name: kparams.FileIoSize, Type: kparams.Uint32, Value: uint32(1024)},
				},
			},
			nil,
			func() *handle.SnapshotterMock {
				hsnap := new(handle.SnapshotterMock)
				hsnap.On("FindByObject", uint64(18446738026482168384)).Return(htypes.Handle{Type: handle.File, Name: "C:\\Windows\\temp\\doc.docx"}, true)
				return hsnap
			},
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, ktypes.WriteFile, e.Type)
				hsnap.AssertNumberOfCalls(t, "FindByObject", 1)
				assert.Contains(t, e.Kparams, kparams.FileName, kparams.FileType)
				assert.Equal(t, "C:\\Windows\\temp\\doc.docx", e.GetParamAsString(kparams.FileName))
				assert.Equal(t, "File", e.GetParamAsString(kparams.FileType))
			},
		},
		{
			"process enum directory",
			&kevent.Kevent{
				Type:     ktypes.EnumDirectory,
				Category: ktypes.File,
				Kparams: kevent.Kparams{
					kparams.FileObject: {Name: kparams.FileObject, Type: kparams.Uint64, Value: uint64(18446738026482168384)},
					kparams.FileKey:    {Name: kparams.FileKey, Type: kparams.Uint64, Value: uint64(14446538026482168384)},
					kparams.FileName:   {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "*"},
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
			func(e *kevent.Kevent, t *testing.T, hsnap *handle.SnapshotterMock, p Processor) {
				assert.Equal(t, ktypes.EnumDirectory, e.Type)
				assert.Contains(t, e.Kparams, kparams.FileName, kparams.FileDirectory)
				assert.Equal(t, "C:\\Windows\\temp", e.GetParamAsString(kparams.FileDirectory))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hsnap := tt.hsnap()
			psnap := new(ps.SnapshotterMock)
			psnap.On("AddFileMapping", mock.Anything).Return(nil)
			psnap.On("RemoveFileMapping", mock.Anything, mock.Anything).Return(nil)
			p := newFsProcessor(hsnap, psnap, fs.NewDevMapper(), fs.NewDevPathResolver(), &config.Config{})
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
