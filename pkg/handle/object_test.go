//go:build windows
// +build windows

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
	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"github.com/rabbitstack/fibratus/pkg/syscall/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"unsafe"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procCreateNamedPipeW = modkernel32.NewProc("CreateNamedPipeW")
)

func createNamedPipe(name *uint16, openMode uint32, pipeMode uint32, maxInstances uint32, outBufSize uint32, inBufSize uint32, defaultTimeout uint32, sa *syscall.SecurityAttributes) (handle syscall.Handle, err error) {
	r0, _, e1 := syscall.Syscall9(procCreateNamedPipeW.Addr(), 8, uintptr(unsafe.Pointer(name)), uintptr(openMode), uintptr(pipeMode), uintptr(maxInstances), uintptr(outBufSize), uintptr(inBufSize), uintptr(defaultTimeout), uintptr(unsafe.Pointer(sa)), 0)
	handle = syscall.Handle(r0)
	if handle == syscall.InvalidHandle {
		if e1 != 0 {
			err = error(e1)
		} else {
			err = syscall.EINVAL
		}
	}
	return
}

// createPipe is mainly borrowed from: https://github.com/natefinch/npipe for testing purposes.
func createPipe(address string, first bool) (syscall.Handle, error) {
	n, err := syscall.UTF16PtrFromString(address)
	if err != nil {
		return 0, err
	}
	mode := uint32(0x3 | syscall.FILE_FLAG_OVERLAPPED)
	if first {
		mode |= 0x00080000
	}
	return createNamedPipe(n,
		mode,
		0x0,
		255,
		512, 512, 0, nil)
}

func TestQueryAllObjectTypes(t *testing.T) {
	otstore := NewObjectTypeStore()
	require.Contains(t, otstore.TypeNames(), "Directory")
	require.Contains(t, otstore.TypeNames(), "Key")
}

func TestQueryType(t *testing.T) {
	h, err := process.Open(process.QueryInformation, false, uint32(os.Getpid()))
	require.NoError(t, err)
	defer h.Close()
	typeName, err := QueryType(h)
	require.NoError(t, err)
	assert.Equal(t, Process, typeName)
}

func TestQueryTypeSmallBuffer(t *testing.T) {
	typeBufSize = 25
	h, err := process.Open(process.QueryInformation, false, uint32(os.Getpid()))
	require.NoError(t, err)
	typeName, err := QueryType(h)
	require.NoError(t, err)
	assert.Equal(t, Process, typeName)
}

func TestQueryNameFileHandle(t *testing.T) {
	f, err := syscall.Open("_fixtures/.fibratus", syscall.O_RDONLY, syscall.S_ISUID)
	require.NoError(t, err)
	defer syscall.Close(f)
	handleName, _, err := QueryName(handle.Handle(f), File, true)
	require.NoError(t, err)
	assert.Equal(t, ".fibratus", filepath.Base(handleName))
}

func TestQueryNamedPipe(t *testing.T) {
	h, err := createPipe(`\\.\pipe\fibratus`, true)
	require.NoError(t, err)
	defer syscall.Close(h)
	handleName, _, err := QueryName(handle.Handle(h), File, true)
	require.NoError(t, err)
	assert.Equal(t, `\Device\NamedPipe\fibratus`, handleName)
}
