/*
 * Copyright 2020-present by Nedim Sabic Sabic
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

package event

import (
	"testing"
	"unsafe"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/stretchr/testify/assert"
)

func TestDecodeRegistry(t *testing.T) {
	var tests = []struct {
		name       string
		buf        []byte
		assertions func(t *testing.T, e *Event)
	}{
		{name: "RegSetValue",
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 3)
				assert.Equal(t, "StartTime", e.Params.MustGetString(params.RegPath))
				assert.Equal(t, uint32(0), e.Params.MustGetUint32(params.NTStatus))
				assert.Equal(t, uint64(0xffffde0e05e45330), e.Params.MustGetUint64(params.RegKCB))
			},
			buf: []byte{
				116, 104, 52, 53, 29, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				48, 83, 228, 5, 14, 222, 255, 255,
				83, 0, 116, 0, 97, 0, 114, 0, 116, 0, 84, 0, 105, 0,
				109, 0, 101, 0, 0, 0},
		},
		{
			name: "RegCreateKey",
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 3)
				assert.Equal(t, `Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\Capabilities`, e.Params.MustGetString(params.RegPath))
				assert.Equal(t, uint32(0), e.Params.MustGetUint32(params.NTStatus))
				assert.Equal(t, uint64(0xffffb58b742ff990), e.Params.MustGetUint64(params.RegKCB))
			},
			buf: []byte{
				248, 104, 16, 11, 5, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				144, 249, 47, 116, 139, 181, 255, 255,
				83, 0, 111, 0, 102, 0, 116, 0,
				119, 0, 97, 0, 114, 0, 101, 0,
				92, 0,
				77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0,
				111, 0, 102, 0, 116, 0,
				92, 0,
				87, 0, 105, 0, 110, 0, 100, 0, 111, 0, 119, 0,
				115, 0,
				92, 0,
				67, 0, 117, 0, 114, 0, 114, 0, 101, 0, 110, 0,
				116, 0, 86, 0, 101, 0, 114, 0, 115, 0, 105, 0,
				111, 0, 110, 0,
				92, 0,
				67, 0, 97, 0, 112, 0, 97, 0, 98, 0, 105, 0,
				108, 0, 105, 0, 116, 0, 121, 0,
				65, 0, 99, 0, 99, 0, 101, 0, 115, 0, 115, 0,
				77, 0, 97, 0, 110, 0, 97, 0, 103, 0, 101, 0,
				114, 0,
				92, 0,
				67, 0, 97, 0, 112, 0, 97, 0, 98, 0, 105, 0,
				108, 0, 105, 0, 116, 0, 105, 0, 101, 0, 115, 0,
				0, 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := initEventRecord(0, 0, tt.buf)
			e := &Event{Params: make(Params)}
			paramDecoder.DecodeRegistry(r, e)
			tt.assertions(t, e)
		})
	}
}

func TestDecodeRegSetValueInternal(t *testing.T) {
	buf := []byte{
		224, 238, 210, 196, 139, 181, 255, 255,
		0, 0, 0, 0,
		1, 0, 0, 0,
		108, 0, 0, 0,
		0, 0,
		85, 0, 82, 0, 73, 0, 0, 0,
		108, 0,
		92, 0,
		77, 0, 105, 0, 99, 0, 114, 0, 111, 0, 115, 0,
		111, 0, 102, 0, 116, 0,
		92, 0,
		87, 0, 105, 0, 110, 0, 100, 0, 111, 0, 119, 0,
		115, 0,
		92, 0,
		70, 0, 108, 0, 105, 0, 103, 0, 104, 0, 116, 0,
		105, 0, 110, 0, 103, 0,
		92, 0,
		79, 0, 110, 0, 101, 0,
		83, 0, 101, 0, 116, 0, 116, 0, 105, 0, 110, 0,
		103, 0, 115, 0,
		92, 0,
		82, 0, 101, 0, 102, 0, 114, 0, 101, 0, 115, 0,
		104, 0,
		67, 0, 97, 0, 99, 0, 104, 0, 101, 0,
		0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}

	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeRegSetValueInternal(r, e)

	assert.Len(t, e.Params, 5)
	assert.Equal(t, "URI", e.Params.MustGetString(params.RegPath))
	assert.Equal(t, uint32(0), e.Params.MustGetUint32(params.NTStatus))
	assert.Equal(t, `\Microsoft\Windows\Flighting\OneSettings\RefreshCache`, e.Params.MustGetString(params.RegData))
	assert.Equal(t, "REG_SZ", e.GetParamAsString(params.RegValueType))
	assert.Equal(t, uint64(0xffffb58bc4d2eee0), e.Params.MustGetUint64(params.RegKeyHandle))
}

func TestDecodeFile(t *testing.T) {
	var tests = []struct {
		name       string
		opcode     uint8
		buf        []byte
		assertions func(t *testing.T, e *Event)
	}{
		{
			name: "CreateFile", opcode: CreateFileID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 7)
				assert.Equal(t, uint64(0xffffd78d965e07c8), e.Params.MustGetUint64(params.FileIrpPtr))
				assert.Equal(t, uint64(0xffffd78d920b6650), e.Params.MustGetUint64(params.FileObject))
				assert.Equal(t, `\Device\HarddiskVolume3\WINDOWS\AppCompat\Programs\Amcache.hve`, e.Params.MustGetString(params.FilePath))
				assert.Equal(t, "NORMAL", e.GetParamAsString(params.FileAttributes))
				assert.Equal(t, "SEQUENTIAL_ONLY|SYNCHRONOUS_IO_NONALERT|NO_COMPRESSION", e.GetParamAsString(params.FileCreateOptions))
				assert.Equal(t, uint32(6536), e.Params.MustGetTid())
			},
			buf: []byte{
				200, 7, 94, 150, 141, 215, 255, 255,
				80, 102, 11, 146, 141, 215, 255, 255,
				136, 25, 0, 0,
				36, 128, 0, 3,
				128, 0, 0, 0,
				0, 0, 0, 0,

				92, 0,
				68, 0, 101, 0, 118, 0, 105, 0, 99, 0, 101, 0,
				92, 0,
				72, 0, 97, 0, 114, 0, 100, 0, 100, 0, 105, 0,
				115, 0, 107, 0,
				86, 0, 111, 0, 108, 0, 117, 0, 109, 0, 101, 0,
				51, 0,
				92, 0,
				87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0,
				83, 0,
				92, 0,
				65, 0, 112, 0, 112, 0,
				67, 0, 111, 0, 109, 0, 112, 0, 97, 0, 116, 0,
				92, 0,
				80, 0, 114, 0, 111, 0, 103, 0, 114, 0, 97, 0,
				109, 0, 115, 0,
				92, 0,
				65, 0, 109, 0, 99, 0, 97, 0, 99, 0, 104, 0,
				101, 0, 46, 0, 104, 0, 118, 0, 101, 0,
				0, 0,
			},
		},
		{
			name: "FileOpEnd", opcode: FileOpEndID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 3)
				assert.Equal(t, uint64(0xffffd78d973df0f8), e.Params.MustGetUint64(params.FileIrpPtr))
				assert.Equal(t, uint32(0), e.Params.MustGetUint32(params.NTStatus))
				assert.Equal(t, uint64(0x28), e.Params.MustGetUint64(params.FileExtraInfo))
			},
			buf: []byte{
				248, 240, 61, 151, 141, 215, 255, 255,
				40, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
		},
		{
			name: "MapViewFile", opcode: MapViewFileID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 7)
				assert.Equal(t, uint64(0xffffb58b75fb7e10), e.Params.MustGetUint64(params.FileKey))
				assert.Equal(t, uint64(0), e.Params.MustGetUint64(params.FileOffset))
				assert.Equal(t, uint32(1716), e.Params.MustGetUint32(params.ProcessID))
				assert.Equal(t, "READONLY", e.GetParamAsString(params.MemProtect))
				assert.Equal(t, "PAGEFILE", e.GetParamAsString(params.FileViewSectionType))
				assert.Equal(t, uint64(0x191ab210000), e.Params.MustGetUint64(params.FileViewBase))
				assert.Equal(t, uint64(4096), e.Params.MustGetUint64(params.FileViewSize))
			},
			buf: []byte{
				0, 0, 33, 171, 145, 1, 0, 0,
				16, 126, 251, 117, 139, 181, 255, 255,
				0, 0, 0, 0, 0, 0, 193, 0,
				0, 16, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				180, 6, 0, 0,
			},
		},
		{
			name: "UnmapViewFile", opcode: UnmapViewFileID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 7)
				assert.Equal(t, uint64(0xffffb58bc1f91010), e.Params.MustGetUint64(params.FileKey))
				assert.Equal(t, uint64(0), e.Params.MustGetUint64(params.FileOffset))
				assert.Equal(t, uint32(12448), e.Params.MustGetUint32(params.ProcessID))
				assert.Equal(t, "READWRITE", e.GetParamAsString(params.MemProtect))
				assert.Equal(t, "PAGEFILE", e.GetParamAsString(params.FileViewSectionType))
				assert.Equal(t, uint64(0x1675e410000), e.Params.MustGetUint64(params.FileViewBase))
				assert.Equal(t, uint64(921600), e.Params.MustGetUint64(params.FileViewSize))
			},
			buf: []byte{
				0, 0, 65, 94, 103, 1, 0, 0,
				16, 16, 249, 193, 139, 181, 255, 255,
				0, 0, 0, 0, 0, 0, 196, 0,
				0, 16, 14, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0,
				160, 48, 0, 0,
			},
		},
		{
			name: "SetFileInformation", opcode: SetFileInformationID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 6)
				assert.Equal(t, "Allocation", e.GetParamAsString(params.FileInfoClass))
				assert.Equal(t, uint64(524288), e.Params.MustGetUint64(params.FileExtraInfo))
				assert.Equal(t, uint64(0xffffb58b80ccc180), e.Params.MustGetUint64(params.FileKey))
				assert.Equal(t, uint64(0xffffd78d76403780), e.Params.MustGetUint64(params.FileObject))
				assert.Equal(t, uint64(0xffffd78d9b6470f8), e.Params.MustGetUint64(params.FileIrpPtr))
				assert.Equal(t, uint32(16404), e.Params.MustGetTid())
			},
			buf: []byte{
				248, 112, 100, 155, 141, 215, 255, 255,
				128, 55, 64, 118, 141, 215, 255, 255,
				128, 193, 204, 128, 139, 181, 255, 255,
				0, 0, 8, 0, 0, 0, 0, 0,
				20, 64, 0, 0,
				19, 0, 0, 0,
			},
		},
		{
			name: "DeleteFile", opcode: DeleteFileID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 6)
				assert.Equal(t, "Disposition Extended", e.GetParamAsString(params.FileInfoClass))
				assert.Equal(t, uint64(1), e.Params.MustGetUint64(params.FileExtraInfo))
				assert.Equal(t, uint64(0xffffb58bc5e64180), e.Params.MustGetUint64(params.FileKey))
				assert.Equal(t, uint64(0xffffd78d9b6c7d80), e.Params.MustGetUint64(params.FileObject))
				assert.Equal(t, uint64(0xffffd78d7c5860f8), e.Params.MustGetUint64(params.FileIrpPtr))
				assert.Equal(t, uint32(13656), e.Params.MustGetTid())
			},
			buf: []byte{
				248, 96, 88, 124, 141, 215, 255, 255,
				128, 125, 108, 155, 141, 215, 255, 255,
				128, 65, 230, 197, 139, 181, 255, 255,
				1, 0, 0, 0, 0, 0, 0, 0,
				88, 53, 0, 0,
				64, 0, 0, 0,
			},
		},
		{
			name: "ReleaseFile", opcode: ReleaseFileID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 4)
				assert.Equal(t, uint64(0xffffb58b9268d180), e.Params.MustGetUint64(params.FileKey))
				assert.Equal(t, uint64(0xffffd78d9b4552b0), e.Params.MustGetUint64(params.FileObject))
				assert.Equal(t, uint64(0xffffd78d7ca0b0f8), e.Params.MustGetUint64(params.FileIrpPtr))
				assert.Equal(t, uint32(3096), e.Params.MustGetTid())
			},
			buf: []byte{
				248, 176, 160, 124, 141, 215, 255, 255,
				176, 82, 69, 155, 141, 215, 255, 255,
				128, 209, 104, 146, 139, 181, 255, 255,
				24, 12, 0, 0,
			},
		},
		{
			name: "WriteFile", opcode: WriteFileID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 6)
				assert.Equal(t, uint64(0xffffb58b74e78b10), e.Params.MustGetUint64(params.FileKey))
				assert.Equal(t, uint64(0xffffd78d6970ae80), e.Params.MustGetUint64(params.FileObject))
				assert.Equal(t, uint64(0xffffd78d9a786a08), e.Params.MustGetUint64(params.FileIrpPtr))
				assert.Equal(t, uint32(392), e.Params.MustGetTid())
				assert.Equal(t, uint64(573440), e.Params.MustGetUint64(params.FileOffset))
				assert.Equal(t, uint32(1073741824), e.Params.MustGetUint32(params.FileIoSize))
			},
			buf: []byte{
				0, 192, 8, 0, 0, 0, 0, 0,
				8, 106, 120, 154, 141, 215, 255, 255,
				128, 174, 112, 105, 141, 215, 255, 255,
				16, 139, 231, 116, 139, 181, 255, 255,
				136, 1, 0, 0,
				0, 64, 1, 0,
				1, 10, 6, 0,
				0, 0, 0, 0,
			},
		},
		{name: "EnumDirectory", opcode: EnumDirectoryID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 6)
				assert.Equal(t, uint64(0xffffde0dfb917590), e.Params.MustGetUint64(params.FileKey))
				assert.Equal(t, uint64(0xffff8084cb43c990), e.Params.MustGetUint64(params.FileObject))
				assert.Equal(t, `git"*`, e.Params.MustGetString(params.FilePath))
				assert.Equal(t, uint64(0xffff8084da3e7788), e.Params.MustGetUint64(params.FileIrpPtr))
				assert.Equal(t, uint32(12860), e.Params.MustGetTid())
			},
			buf: []byte{
				136, 119, 62, 218, 132, 128, 255, 255,
				144, 201, 67, 203, 132, 128, 255, 255,
				144, 117, 145, 251, 13, 222, 255, 255,
				60, 50, 0, 0, 116, 2, 0, 0,
				79, 0, 0, 0, 0, 0, 0, 0,
				103, 0, 105, 0, 116, 0, 34, 0, 42, 0, 0, 0,
			},
		},
		{
			name: "FileRundown", opcode: FileRundownID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 2)
				assert.Equal(t, `\Device\HarddiskVolume3\Windows\System32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-TerminalServices-AppServerClient-Opt-WOW64-Package~31bf3856ad364e35~wow64~~10.0.26100.8115.cat`, e.Params.MustGetString(params.FilePath))
			},
			buf: []byte{
				80, 71, 18, 158, 139, 181, 255, 255,
				92, 0, 68, 0, 101, 0, 118, 0,
				105, 0, 99, 0, 101, 0, 92, 0,
				72, 0, 97, 0, 114, 0, 100, 0,
				100, 0, 105, 0, 115, 0, 107, 0,
				86, 0, 111, 0, 108, 0, 117, 0,
				109, 0, 101, 0, 51, 0, 92, 0,
				87, 0, 105, 0, 110, 0, 100, 0,
				111, 0, 119, 0, 115, 0, 92, 0,
				83, 0, 121, 0, 115, 0, 116, 0,
				101, 0, 109, 0, 51, 0, 50, 0,
				92, 0, 67, 0, 97, 0, 116, 0,
				82, 0, 111, 0, 111, 0, 116, 0,
				92, 0,
				123, 0, 70, 0, 55, 0, 53, 0, 48, 0,
				69, 0, 54, 0, 67, 0, 51, 0, 45, 0,
				51, 0, 56, 0, 69, 0, 69, 0, 45, 0,
				49, 0, 49, 0, 68, 0, 49, 0, 45, 0,
				56, 0, 53, 0, 69, 0, 53, 0, 45, 0,
				48, 0, 48, 0, 67, 0, 48, 0, 52, 0,
				70, 0, 67, 0, 50, 0, 57, 0, 53, 0,
				69, 0, 69, 0, 125, 0,
				92, 0,
				77, 0, 105, 0, 99, 0, 114, 0, 111, 0,
				115, 0, 111, 0, 102, 0, 116, 0, 45, 0,
				87, 0, 105, 0, 110, 0, 100, 0, 111, 0,
				119, 0, 115, 0, 45, 0,
				84, 0, 101, 0, 114, 0, 109, 0, 105, 0,
				110, 0, 97, 0, 108, 0,
				83, 0, 101, 0, 114, 0, 118, 0, 105, 0,
				99, 0, 101, 0, 115, 0, 45, 0,
				65, 0, 112, 0, 112, 0, 83, 0, 101, 0,
				114, 0, 118, 0, 101, 0, 114, 0,
				67, 0, 108, 0, 105, 0, 101, 0, 110, 0,
				116, 0, 45, 0,
				79, 0, 112, 0, 116, 0, 45, 0,
				87, 0, 79, 0, 87, 0, 54, 0, 52, 0,
				45, 0,
				80, 0, 97, 0, 99, 0, 107, 0, 97, 0,
				103, 0, 101, 0,
				126, 0, 51, 0, 49, 0, 98, 0, 102, 0,
				51, 0, 56, 0, 53, 0, 54, 0, 97, 0,
				100, 0, 51, 0, 54, 0, 52, 0, 101, 0,
				51, 0, 53, 0, 126, 0,
				119, 0, 111, 0, 119, 0, 54, 0, 52, 0,
				126, 0, 126, 0,
				49, 0, 48, 0, 46, 0, 48, 0, 46, 0,
				50, 0, 54, 0, 49, 0, 48, 0, 48, 0,
				46, 0, 56, 0, 49, 0, 49, 0, 53, 0,
				46, 0,
				99, 0, 97, 0, 116, 0,
				0, 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := initEventRecord(tt.opcode, 0, tt.buf)
			e := &Event{Params: make(Params)}
			paramDecoder.DecodeFile(r, e)
			tt.assertions(t, e)
		})
	}
}

func TestDecodeProcess(t *testing.T) {
	buf := []byte{
		192, 48, 161, 124, 141, 215, 255, 255,
		124, 78, 0, 0,
		128, 52, 0, 0,
		1, 0, 0, 0,
		3, 1, 0, 0,
		0, 96, 231, 68, 3, 0, 0, 0,
		0, 0, 0, 0,
		160, 162, 152, 216, 139, 181, 255, 255,
		0, 0, 0, 0, 0, 0, 0, 0,

		1, 5, 0, 0, 0, 0, 0, 5,
		21, 0, 0, 0,
		226, 73, 191, 35, 149, 112, 61, 68,
		44, 66, 142, 178, 234, 3, 0, 0,

		99, 111, 110, 104, 111, 115, 116, 46, 101, 120, 101, 0,

		92, 0, 63, 0, 63, 0, 92, 0,
		67, 0, 58, 0, 92, 0, 87, 0, 73, 0, 78, 0, 68, 0, 79, 0, 87, 0, 83, 0,
		92, 0, 115, 0, 121, 0, 115, 0, 116, 0, 101, 0, 109, 0, 51, 0, 50, 0,
		92, 0, 99, 0, 111, 0, 110, 0, 104, 0, 111, 0, 115, 0, 116, 0, 46, 0,
		101, 0, 120, 0, 101, 0,

		32, 0, 48, 0, 120, 0, 102, 0, 102, 0, 102, 0, 102, 0, 102, 0, 102, 0, 102, 0,
		32, 0, 45, 0, 70, 0, 111, 0, 114, 0, 99, 0, 101, 0, 86, 0, 49, 0,

		0, 0, 0, 0, 0, 0, 0, 0,
	}

	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeProcess(r, e)

	assert.Len(t, e.Params, 11)
	assert.Equal(t, `\??\C:\WINDOWS\system32\conhost.exe 0xfffffff -ForceV1`, e.Params.MustGetString(params.Cmdline))
	assert.Equal(t, uint64(0x344e76000), e.Params.MustGetUint64(params.DTB))
	assert.Equal(t, uint32(0x103), e.Params.MustGetUint32(params.ExitStatus))
	assert.Equal(t, uint64(0xffffd78d7ca130c0), e.Params.MustGetUint64(params.ProcessObject))
	assert.Equal(t, "conhost.exe", e.Params.MustGetString(params.ProcessName))
	assert.Equal(t, uint32(20092), e.Params.MustGetPid())
	assert.Equal(t, uint32(13440), e.Params.MustGetPpid())
	assert.Equal(t, uint32(13440), e.Params.MustGetUint32(params.ProcessRealParentID))
	assert.Equal(t, uint32(1), e.Params.MustGetUint32(params.SessionID))
	assert.Equal(t, "S-1-5-21-599738850-1144877205-2995667500-1002", e.GetParamAsString(params.UserSID))
}

func TestDecodeProcessInternal(t *testing.T) {
	buf := []byte{
		88, 77, 0, 0,
		13, 195, 0, 0,
		0, 0, 0, 0,

		102, 161, 153, 7, 34, 222, 220, 1,

		172, 26, 0, 0,
		11, 195, 0, 0,
		0, 0, 0, 0,

		1, 0, 0, 0,
		0, 0, 0, 0,
		2, 0, 0, 0,
		1, 0, 0, 0,
		1, 1, 0, 0,

		0, 0, 0, 16,
		0, 48, 0, 0,

		92, 0,
		68, 0, 101, 0, 118, 0, 105, 0, 99, 0, 101, 0,
		92, 0,
		72, 0, 97, 0, 114, 0, 100, 0, 100, 0, 105, 0,
		115, 0, 107, 0,
		86, 0, 111, 0, 108, 0, 117, 0, 109, 0, 101, 0,
		51, 0,
		92, 0,
		80, 0, 114, 0, 111, 0, 103, 0, 114, 0, 97, 0,
		109, 0,
		32, 0,
		70, 0, 105, 0, 108, 0, 101, 0, 115, 0,
		92, 0,
		71, 0, 105, 0, 116, 0,
		92, 0,
		109, 0, 105, 0, 110, 0, 103, 0, 119, 0, 54, 0,
		52, 0,
		92, 0,
		98, 0, 105, 0, 110, 0,
		92, 0,
		103, 0, 105, 0, 116, 0, 46, 0, 101, 0, 120, 0,
		101, 0,
		0, 0,

		95, 10, 66, 0,
		139, 104, 27, 105,

		0, 0, 0, 0, 0, 0, 0, 0,
	}

	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeProcessInternal(r, e)

	assert.Len(t, e.Params, 10)
	assert.Equal(t, `\Device\HarddiskVolume3\Program Files\Git\mingw64\bin\git.exe`, e.Params.MustGetString(params.Exe))
	assert.Equal(t, uint64(0xc30d), e.Params.MustGetUint64(params.ProcessObject))
	assert.Equal(t, uint32(19800), e.Params.MustGetPid())
	assert.Equal(t, uint32(6828), e.Params.MustGetPpid())
	assert.Equal(t, uint32(1), e.Params.MustGetUint32(params.SessionID))
	assert.Equal(t, "FULL", e.GetParamAsString(params.ProcessTokenElevationType))
	assert.Equal(t, "HIGH", e.GetParamAsString(params.ProcessTokenIntegrityLevel))
	assert.True(t, e.Params.MustGetBool(params.ProcessTokenIsElevated))
}

func TestDecodeModule(t *testing.T) {
	buf := []byte{
		0, 0, 32, 9, 253, 127, 0, 0,
		0, 128, 0, 0, 0, 0, 0, 0,
		168, 21, 0, 0,
		93, 190, 0, 0,
		32, 96, 25, 187, 12, 7, 0, 0,

		0, 0, 32, 9, 253, 127, 0, 0,

		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,

		92, 0,
		68, 0, 101, 0, 118, 0, 105, 0, 99, 0, 101, 0,
		92, 0,
		72, 0, 97, 0, 114, 0, 100, 0, 100, 0, 105, 0,
		115, 0, 107, 0,
		86, 0, 111, 0, 108, 0, 117, 0, 109, 0, 101, 0,
		51, 0,
		92, 0,
		87, 0, 105, 0, 110, 0, 100, 0, 111, 0, 119, 0,
		115, 0,
		92, 0,
		83, 0, 121, 0, 115, 0, 116, 0, 101, 0, 109, 0,
		51, 0, 50, 0,
		92, 0,
		110, 0, 111, 0, 114, 0, 109, 0, 97, 0, 108, 0,
		105, 0, 122, 0, 46, 0,
		100, 0, 108, 0, 108, 0,
		0, 0,
	}

	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeModule(r, e)

	assert.Len(t, e.Params, 8)
	assert.Equal(t, uint64(0x7ffd09200000), e.Params.MustGetUint64(params.ModuleBase))
	assert.Equal(t, uint32(48733), e.Params.MustGetUint32(params.ModuleCheckSum))
	assert.Equal(t, uint64(0x7ffd09200000), e.Params.MustGetUint64(params.ModuleDefaultBase))
	assert.Equal(t, `\Device\HarddiskVolume3\Windows\System32\normaliz.dll`, e.Params.MustGetString(params.ModulePath))
	assert.Equal(t, uint64(32768), e.Params.MustGetUint64(params.ModuleSize))
	assert.Equal(t, uint32(5544), e.Params.MustGetPid())
	assert.Equal(t, "WINDOWS", e.GetParamAsString(params.ModuleSignatureLevel))
	assert.Equal(t, "FILE_VERIFIED", e.GetParamAsString(params.ModuleSignatureType))
}

func TestDecodeModuleInternal(t *testing.T) {
	buf := []byte{
		0, 0, 150, 252, 252, 127, 0, 0,
		0, 96, 8, 0, 0, 0, 0, 0,
		96, 68, 0, 0,
		231, 125, 8, 0,
		42, 234, 60, 109, 0, 0,

		150, 252, 252, 127, 0, 0,

		92, 0,
		68, 0, 101, 0, 118, 0, 105, 0, 99, 0, 101, 0,
		92, 0,
		72, 0, 97, 0, 114, 0, 100, 0, 100, 0, 105, 0,
		115, 0, 107, 0,
		86, 0, 111, 0, 108, 0, 117, 0, 109, 0, 101, 0,
		51, 0,
		92, 0,
		87, 0, 105, 0, 110, 0, 100, 0, 111, 0, 119, 0,
		115, 0,
		92, 0,
		83, 0, 121, 0, 115, 0, 116, 0, 101, 0, 109, 0,
		51, 0, 50, 0,
		92, 0,
		70, 0, 87, 0, 80, 0, 85, 0, 67, 0, 76, 0,
		78, 0, 84, 0, 46, 0,
		68, 0, 76, 0, 76, 0,
		0, 0,
	}

	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeModuleInternal(r, e)

	assert.Len(t, e.Params, 6)
	assert.Equal(t, uint64(0x7ffcfc960000), e.Params.MustGetUint64(params.ModuleBase))
	assert.Equal(t, uint32(556519), e.Params.MustGetUint32(params.ModuleCheckSum))
	assert.Equal(t, uint64(0x7ffcfc960000), e.Params.MustGetUint64(params.ModuleDefaultBase))
	assert.Equal(t, `\Device\HarddiskVolume3\Windows\System32\FWPUCLNT.DLL`, e.Params.MustGetString(params.ModulePath))
	assert.Equal(t, uint64(548864), e.Params.MustGetUint64(params.ModuleSize))
	assert.Equal(t, uint32(17504), e.Params.MustGetPid())
}

func TestDecodeOpenProcess(t *testing.T) {
	buf := []byte{
		112, 22, 0, 0,
		0, 16, 0, 0,
		0, 0, 0, 0,
	}

	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeOpenProcess(r, e)

	assert.Len(t, e.Params, 4)
	assert.Equal(t, "QUERY_LIMITED_INFORMATION", e.GetParamAsString(params.DesiredAccess))
	assert.Equal(t, uint32(5744), e.Params.MustGetPid())
	assert.Equal(t, uint32(0), e.Params.MustGetUint32(params.NTStatus))
}

func TestDecodeThread(t *testing.T) {
	buf := []byte{
		8, 20, 0, 0,
		228, 6, 0, 0,
		0, 128,
		128, 12, 10, 252, 255, 255,
		0, 16,
		128, 12, 10, 252, 255, 255,
		0, 0,
		16, 206, 88, 0, 0, 0, 0, 128,
		15, 206, 88, 0, 0, 0, 255, 255,
		0, 0, 0, 0,
		128, 90, 99, 9, 253, 127, 0, 0,
		0, 240, 233, 205, 88, 0, 0, 0,
		0, 0, 0, 0,
		8, 5, 2, 0,
		0, 0,
	}

	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeThread(r, e)

	assert.Len(t, e.Params, 11)
	assert.Equal(t, uint8(2), e.Params.MustGetUint8(params.BasePrio))
	assert.Equal(t, uint8(0), e.Params.MustGetUint8(params.IOPrio))
	assert.Equal(t, uint8(0), e.Params.MustGetUint8(params.PagePrio))
	assert.Equal(t, uint64(0xfffffc0a0c808000), e.Params.MustGetUint64(params.KstackBase))
	assert.Equal(t, uint64(0xfffffc0a0c801000), e.Params.MustGetUint64(params.KstackLimit))
	assert.Equal(t, uint32(5128), e.Params.MustGetPid())
	assert.Equal(t, uint32(1764), e.Params.MustGetTid())
	assert.Equal(t, uint64(0xf00000007ffd0963), e.Params.MustGetUint64(params.StartAddress))
	assert.Equal(t, uint64(0x58cde9), e.Params.MustGetUint64(params.TEB))
	assert.Equal(t, uint64(0x58ce100000), e.Params.MustGetUint64(params.UstackBase))
	assert.Equal(t, uint64(0x58ce0f8000), e.Params.MustGetUint64(params.UstackLimit))
}

func TestDecodeOpenThread(t *testing.T) {
	buf := []byte{
		104, 17, 0, 0,
		76, 47, 0, 0,
		255, 255, 31, 0,
		0, 0, 0, 0,
	}

	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeOpenThread(r, e)

	assert.Len(t, e.Params, 5)
	assert.Equal(t, "ALL_ACCESS", e.GetParamAsString(params.DesiredAccess))
	assert.Equal(t, uint32(4456), e.Params.MustGetPid())
	assert.Equal(t, uint32(12108), e.Params.MustGetTid())
	assert.Equal(t, uint32(0), e.Params.MustGetUint32(params.NTStatus))
}

func TestDecodeSetThreadContext(t *testing.T) {
	buf := []byte{
		0, 0, 0, 0,
	}
	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeSetThreadContext(r, e)

	assert.Len(t, e.Params, 2)
	assert.Equal(t, uint32(0), e.Params.MustGetUint32(params.NTStatus))
}

func TestDecodeCreateSymbolicLinkObject(t *testing.T) {
	buf := []byte{
		83, 0, 101, 0, 115, 0, 115, 0,
		105, 0, 111, 0, 110, 0, 0, 0,

		92, 0, 83, 0, 101, 0, 115, 0,
		115, 0, 105, 0, 111, 0, 110, 0,
		115, 0, 92, 0,
		49, 0,
		92, 0,
		65, 0, 112, 0, 112, 0,
		67, 0, 111, 0, 110, 0, 116, 0,
		97, 0, 105, 0, 110, 0, 101, 0,
		114, 0,
		78, 0, 97, 0, 109, 0, 101, 0,
		100, 0,
		79, 0, 98, 0, 106, 0, 101, 0,
		99, 0, 116, 0, 115, 0,
		92, 0,

		83, 0, 45, 0,
		49, 0, 45, 0,
		49, 0, 53, 0, 45, 0,
		50, 0, 45, 0,
		49, 0, 54, 0, 48, 0, 57, 0,
		52, 0, 55, 0, 51, 0, 55, 0,
		57, 0, 56, 0, 45, 0,
		49, 0, 50, 0, 51, 0, 49, 0,
		57, 0, 50, 0, 51, 0, 48, 0,
		49, 0, 55, 0, 45, 0,
		54, 0, 56, 0, 52, 0, 50, 0,
		54, 0, 56, 0, 49, 0, 53, 0,
		51, 0, 45, 0,
		52, 0, 50, 0, 54, 0, 56, 0,
		53, 0, 49, 0, 52, 0, 51, 0,
		50, 0, 56, 0, 45, 0,
		56, 0, 56, 0, 50, 0, 55, 0,
		55, 0, 51, 0, 54, 0, 52, 0,
		54, 0, 45, 0,
		50, 0, 55, 0, 54, 0, 48, 0,
		53, 0, 56, 0, 53, 0, 55, 0,
		55, 0, 51, 0, 45, 0,
		49, 0, 55, 0, 54, 0, 48, 0,
		57, 0, 51, 0, 56, 0, 49, 0,
		53, 0, 55, 0,
		0, 0,

		1, 0,
		15, 0,
		0, 0, 0, 0,
	}

	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeCreateSymbolicLinkObject(r, e)

	assert.Len(t, e.Params, 5)
	assert.Equal(t, "DELETE|READ_CONTROL|WRITE_DAC|WRITE_OWNER", e.GetParamAsString(params.DesiredAccess))
	assert.Equal(t, "Session", e.GetParamAsString(params.LinkSource))
	assert.Equal(t, `\Sessions\1\AppContainerNamedObjects\S-1-15-2-1609473798-1231923017-684268153-4268514328-882773646-2760585773-1760938157`, e.GetParamAsString(params.LinkTarget))
	assert.Equal(t, uint32(0), e.Params.MustGetUint32(params.NTStatus))
}

func TestDecodeStackWalk(t *testing.T) {
	buf := []byte{
		41, 41, 119, 69, 58, 0, 0, 0,
		12, 15, 0, 0,
		160, 29, 0, 0,

		148, 12, 254, 189, 5, 248, 255, 255,
		175, 137, 229, 189, 5, 248, 255, 255,
		134, 47, 242, 189, 5, 248, 255, 255,
		36, 109, 255, 80, 5, 248, 255, 255,
		175, 186, 130, 79, 5, 248, 255, 255,
		160, 177, 130, 79, 5, 248, 255, 255,
		224, 104, 137, 79, 5, 248, 255, 255,
		59, 149, 250, 189, 5, 248, 255, 255,
		179, 148, 250, 189, 5, 248, 255, 255,
		59, 168, 73, 190, 5, 248, 255, 255,
		218, 136, 73, 190, 5, 248, 255, 255,
		227, 101, 73, 190, 5, 248, 255, 255,
		196, 202, 73, 190, 5, 248, 255, 255,
		85, 217, 43, 190, 5, 248, 255, 255,

		20, 69, 114, 9, 253, 127, 0, 0,
		31, 51, 25, 6, 253, 127, 0, 0,
		105, 96, 138, 36, 246, 127, 0, 0,
		109, 37, 146, 36, 246, 127, 0, 0,
		227, 37, 146, 36, 246, 127, 0, 0,
	}

	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeStackwalk(r, e)

	assert.Len(t, e.Params, 3)
	assert.Equal(t, uint32(3852), e.Params.MustGetPid())
	assert.Equal(t, uint32(7584), e.Params.MustGetTid())
	assert.Equal(t, []va.Address{0xfffff805bdfe0c94, 0xfffff805bde589af, 0xfffff805bdf22f86, 0xfffff80550ff6d24, 0xfffff8054f82baaf, 0xfffff8054f82b1a0, 0xfffff8054f8968e0, 0xfffff805bdfa953b, 0xfffff805bdfa94b3, 0xfffff805be49a83b, 0xfffff805be4988da, 0xfffff805be4965e3, 0xfffff805be49cac4, 0xfffff805be2bd955, 0x7ffd09724514, 0x7ffd0619331f, 0x7ff6248a6069, 0x7ff62492256d, 0x7ff6249225e3}, e.Params.MustGetSlice(params.Callstack))
}

func TestDecodeMemory(t *testing.T) {
	buf := []byte{
		0, 176, 27, 242, 110, 2, 0, 0,
		0, 16, 0, 0, 0, 0, 0, 0,
		112, 13, 0, 0,
		0, 16, 0, 0,
	}

	r := initEventRecord(0, 0, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeMemory(r, e)

	assert.Len(t, e.Params, 4)
	assert.Equal(t, uint32(3440), e.Params.MustGetPid())
	assert.Equal(t, uint64(4096), e.Params.MustGetUint64(params.MemRegionSize))
	assert.Equal(t, uint64(0x26ef21bb000), e.Params.MustGetUint64(params.MemBaseAddress))
	assert.Equal(t, "COMMIT", e.GetParamAsString(params.MemAllocType))
}

func TestDecodeNetwork(t *testing.T) {
	var tests = []struct {
		name       string
		opcode     uint8
		buf        []byte
		assertions func(t *testing.T, e *Event)
	}{
		{
			name: "SendTCPv4", opcode: SendV4ID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 6)
				assert.Equal(t, "172.64.148.235", e.GetParamAsString(params.NetDIP))
				assert.Equal(t, uint16(443), e.Params.MustGetUint16(params.NetDport))
				assert.Equal(t, "192.168.1.44", e.GetParamAsString(params.NetSIP))
				assert.Equal(t, uint16(61552), e.Params.MustGetUint16(params.NetSport))
				assert.Equal(t, uint32(12448), e.Params.MustGetPid())
				assert.Equal(t, uint32(28), e.Params.MustGetUint32(params.NetSize))
			},
			buf: []byte{
				160, 48, 0, 0,
				28, 0, 0, 0,
				172, 64, 148, 235,
				192, 168, 1, 44,
				1, 187, 240, 112,
				106, 198, 40, 0,
				107, 198, 40, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
		},
		{
			name: "ConnectTCPv4", opcode: ConnectTCPv4ID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 6)
				assert.Equal(t, "151.101.193.91", e.GetParamAsString(params.NetDIP))
				assert.Equal(t, uint16(443), e.Params.MustGetUint16(params.NetDport))
				assert.Equal(t, "192.168.1.44", e.GetParamAsString(params.NetSIP))
				assert.Equal(t, uint16(61931), e.Params.MustGetUint16(params.NetSport))
				assert.Equal(t, uint32(12448), e.Params.MustGetPid())
				assert.Equal(t, uint32(0), e.Params.MustGetUint32(params.NetSize))
			},
			buf: []byte{
				160, 48, 0, 0,
				0, 0, 0, 0,
				151, 101, 193, 91,
				192, 168, 1, 44,
				1, 187, 241, 235,
				0, 0, 1, 0,
				255, 255, 0, 0,
				8, 0, 9, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
			},
		},
		{
			name: "RecvUDPv6", opcode: RecvV6ID,
			assertions: func(t *testing.T, e *Event) {
				assert.Len(t, e.Params, 6)
				assert.Equal(t, "ff02::c", e.GetParamAsString(params.NetDIP))
				assert.Equal(t, uint16(1900), e.Params.MustGetUint16(params.NetDport))
				assert.Equal(t, "fe80::1", e.GetParamAsString(params.NetSIP))
				assert.Equal(t, uint16(56797), e.Params.MustGetUint16(params.NetSport))
				assert.Equal(t, uint32(5128), e.Params.MustGetPid())
				assert.Equal(t, uint32(127), e.Params.MustGetUint32(params.NetSize))
			},
			buf: []byte{
				8, 20, 0, 0,
				127, 0, 0, 0,
				255, 2, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 12,
				254, 128, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 0,
				0, 0, 0, 1, 7, 108,
				221, 221, 0, 0, 0, 0,
				0, 0, 0, 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := initEventRecord(tt.opcode, 0, tt.buf)
			e := &Event{Params: make(Params)}
			paramDecoder.DecodeNetwork(r, e)
			tt.assertions(t, e)
		})
	}
}

func TestDecodeDNS(t *testing.T) {
	buf := []byte{
		105, 0, 109, 0, 103, 0, 45, 0,
		112, 0, 114, 0, 111, 0, 100, 0,
		46, 0,
		112, 0, 111, 0, 99, 0, 107, 0,
		101, 0, 116, 0, 46, 0,
		112, 0, 114, 0, 111, 0, 100, 0,
		46, 0,
		99, 0, 108, 0, 111, 0, 117, 0,
		100, 0, 111, 0, 112, 0, 115, 0,
		46, 0,
		109, 0, 111, 0, 122, 0, 103, 0,
		99, 0, 112, 0, 46, 0,
		110, 0, 101, 0, 116, 0,
		0, 0,

		28, 0, 0, 0,
		193, 8, 16, 0,
		0, 128, 0, 0,
		0, 0, 0, 0,

		50, 0, 54, 0, 48, 0, 48, 0,
		58, 0, 49, 0, 57, 0, 48, 0,
		49, 0, 58, 0, 48, 0,
		58, 0, 101, 0, 57, 0, 56, 0,
		56, 0, 58, 0, 58, 0,
		59, 0,
		0, 0,
	}

	r := initEventRecord(0, ReplyDNSID, buf)
	e := &Event{Params: make(Params)}
	paramDecoder.DecodeDNS(r, e)

	assert.Len(t, e.Params, 5)
	assert.Equal(t, []string{"2600:1901:0:e988::", ""}, e.Params.MustGetSlice(params.DNSAnswers))
	assert.Equal(t, "img-prod.pocket.prod.cloudops.mozgcp.net", e.Params.MustGetString(params.DNSName))
	assert.Equal(t, "ACCEPT_TRUNCATED_RESPONSE|NO_NETBT|NO_MULTICAST|DONT_RESET_TTL_VALUES", e.GetParamAsString(params.DNSOpts))
	assert.Equal(t, "NOERROR", e.GetParamAsString(params.DNSRcode))
	assert.Equal(t, "AAAA", e.GetParamAsString(params.DNSRR))
}

func initEventRecord(opcode uint8, id uint16, buf []byte) *etw.EventRecord {
	return &etw.EventRecord{
		Header: etw.EventHeader{
			ProcessID: 13440,
			EventDescriptor: etw.EventDescriptor{
				Opcode: opcode,
				ID:     id,
			},
		},
		BufferLen: uint16(len(buf)),
		Buffer:    uintptr(unsafe.Pointer(&buf[0])),
	}
}
