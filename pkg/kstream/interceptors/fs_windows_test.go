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

package interceptors

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

type devMapperMock struct {
	mock.Mock
}

func (dm *devMapperMock) Convert(filename string) string {
	args := dm.Called(filename)
	return args.String(0)
}

func init() {
	rundownDeadlinePeriod = time.Millisecond * 200
}

func TestCreateFile(t *testing.T) {
	devMapper := new(devMapperMock)
	hsnapMock := new(handle.SnapshotterMock)

	sysRoot := os.Getenv("SystemRoot")
	devMapper.On("Convert", "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll").Return(fmt.Sprintf("%s\\system32\\user32.dll", sysRoot))

	fsi := newFsInterceptor(devMapper, hsnapMock, &config.Config{}, nil)

	_, _, err := fsi.Intercept(&kevent.Kevent{
		Type: ktypes.FileRundown,
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.FileObject: {Name: kparams.FileObject, Type: kparams.Uint64, Value: kparams.Hex("12456738026482168384")},
			kparams.FileName:   {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
			kparams.FileIrpPtr: {Name: kparams.FileIrpPtr, Type: kparams.Uint64, Value: kparams.Hex("1234543123112321")},
		},
	})
	require.NoError(t, err)

	kevt1 := &kevent.Kevent{
		Type: ktypes.CreateFile,
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.FileObject:        {Name: kparams.FileObject, Type: kparams.Uint64, Value: kparams.Hex("18446738026482168384")},
			kparams.ThreadID:          {Name: kparams.ThreadID, Type: kparams.Uint32, Value: uint32(1484)},
			kparams.FileCreateOptions: {Name: kparams.FileCreateOptions, Type: kparams.Uint32, Value: uint32(1223456)},
			kparams.FileName:          {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll"},
			kparams.FileShareMask:     {Name: kparams.FileShareMask, Type: kparams.Uint32, Value: uint32(5)},
			kparams.FileIrpPtr:        {Name: kparams.FileIrpPtr, Type: kparams.Uint64, Value: kparams.Hex("1234543123112321")},
		},
	}
	devMapper.On("Convert", "\\Device\\HarddiskVolume2\\Windows\\system32\\kernel32.dll").Return(fmt.Sprintf("%s\\system32\\kernel32.dll", sysRoot))

	_, _, err = fsi.Intercept(kevt1)
	require.EqualErrorf(t, err, "cancel bubbling up the kernel event to upstream components", "")

	pendingKevents := fsi.(*fsInterceptor).pendingKevents
	require.Len(t, pendingKevents, 1)

	opEnd := &kevent.Kevent{
		Type: ktypes.FileOpEnd,
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.FileObject:    {Name: kparams.FileObject, Type: kparams.Uint64, Value: kparams.Hex("18446738026482168384")},
			kparams.ThreadID:      {Name: kparams.ThreadID, Type: kparams.Uint32, Value: uint32(1484)},
			kparams.FileIrpPtr:    {Name: kparams.FileIrpPtr, Type: kparams.Uint64, Value: kparams.Hex("1234543123112321")},
			kparams.FileExtraInfo: {Name: kparams.FileExtraInfo, Type: kparams.Uint8, Value: kparams.Hex("2")},
		},
	}
	kevt1, _, err = fsi.Intercept(opEnd)
	require.NoError(t, err)

	dispo, err := kevt1.Kparams.Get(kparams.FileOperation)
	require.NoError(t, err)
	assert.Equal(t, fs.Create, dispo.(fs.FileDisposition))
	filename, err := kevt1.Kparams.GetString(kparams.FileName)
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%s\\system32\\kernel32.dll", sysRoot), filename)
	mask, err := kevt1.Kparams.Get(kparams.FileShareMask)
	require.NoError(t, err)
	assert.Equal(t, "r-d", mask.(fs.FileShareMode).String())

	require.Empty(t, pendingKevents)
}

func TestRundownFile(t *testing.T) {
	devMapper := new(devMapperMock)
	hsnapMock := new(handle.SnapshotterMock)

	sysRoot := os.Getenv("SystemRoot")
	devMapper.On("Convert", "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll").Return(fmt.Sprintf("%s\\system32\\user32.dll", sysRoot))

	fsi := newFsInterceptor(devMapper, hsnapMock, &config.Config{}, nil)

	_, _, err := fsi.Intercept(&kevent.Kevent{
		Type: ktypes.FileRundown,
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.FileObject: {Name: kparams.FileObject, Type: kparams.Uint64, Value: kparams.Hex("124567380264")},
			kparams.FileName:   {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
		},
	})
	require.NoError(t, err)

	files := fsi.(*fsInterceptor).files
	require.Len(t, files, 1)

	fileinfo := files[20089293767268]
	require.NotNil(t, fileinfo)

	assert.Equal(t, fmt.Sprintf("%s\\system32\\user32.dll", sysRoot), fileinfo.name)
	assert.Equal(t, fs.Regular, fileinfo.typ)
}

func TestDeleteFile(t *testing.T) {
	devMapper := new(devMapperMock)
	hsnapMock := new(handle.SnapshotterMock)

	sysRoot := os.Getenv("SystemRoot")
	devMapper.On("Convert", "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll").Return(fmt.Sprintf("%s\\system32\\user32.dll", sysRoot))

	fsi := newFsInterceptor(devMapper, hsnapMock, &config.Config{}, nil)

	_, _, err := fsi.Intercept(&kevent.Kevent{
		Type: ktypes.FileRundown,
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.FileObject: {Name: kparams.FileObject, Type: kparams.Uint64, Value: kparams.Hex("12456738026482168384")},
			kparams.FileName:   {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"},
		},
	})
	require.NoError(t, err)

	kevt := &kevent.Kevent{
		Type: ktypes.DeleteFile,
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.FileObject: {Name: kparams.FileObject, Type: kparams.Uint64, Value: kparams.Hex("12456738026482168384")},
			kparams.FileKey:    {Name: kparams.FileKey, Type: kparams.Uint64, Value: kparams.Hex("12456738026482168384")},
			kparams.ThreadID:   {Name: kparams.ThreadID, Type: kparams.Uint32, Value: uint32(1484)},
		},
	}

	files := fsi.(*fsInterceptor).files
	require.Len(t, files, 1)

	_, _, err = fsi.Intercept(kevt)
	require.NoError(t, err)

	require.Empty(t, files)

	filename, err := kevt.Kparams.GetString(kparams.FileName)
	require.NoError(t, err)

	assert.Equal(t, fmt.Sprintf("%s\\system32\\user32.dll", sysRoot), filename)
	typ, err := kevt.Kparams.GetString(kparams.FileType)
	require.NoError(t, err)
	assert.Equal(t, "file", typ)
}

func TestRundownFileDeadline(t *testing.T) {
	devMapper := new(devMapperMock)
	hsnapMock := new(handle.SnapshotterMock)

	sysRoot := os.Getenv("SystemRoot")
	devMapper.On("Convert", "\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll").Return(fmt.Sprintf("%s\\system32\\user32.dll", sysRoot))

	ch := make(chan bool, 1)
	fn := func() error {
		ch <- true
		return nil
	}

	newFsInterceptor(devMapper, hsnapMock, &config.Config{}, fn)

	<-ch
}
