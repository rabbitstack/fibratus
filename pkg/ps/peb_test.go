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

package ps

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadPEB(t *testing.T) {
	desiredAccess := uint32(windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ)
	proc, err := windows.OpenProcess(desiredAccess, false, uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	//nolint:errcheck
	defer windows.CloseHandle(proc)

	peb, err := ReadPEB(proc)
	require.NoError(t, err)

	assert.Equal(t, "ps.test.exe", filepath.Base(peb.GetImage()))
	assert.Equal(t, "ps", filepath.Base(peb.GetCurrentWorkingDirectory()))

	args := strings.Fields(peb.GetCommandLine())
	assert.True(t, len(args) > 1)
	assert.Contains(t, args, "-test.timeout=10m0s")

	assert.Contains(t, peb.GetEnvs(), "COMPUTERNAME")
}
