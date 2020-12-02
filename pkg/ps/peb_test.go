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
	"github.com/rabbitstack/fibratus/pkg/syscall/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestPEBGetCurrentWorkingDirectory(t *testing.T) {
	flags := process.QueryInformation | process.VMRead
	handle, err := process.Open(flags, false, uint32(os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	peb, err := ReadPEB(handle)
	require.NoError(t, err)

	cwd := peb.GetCurrentWorkingDirectory()
	require.NotEmpty(t, cwd)
	assert.Equal(t, "ps", filepath.Base(cwd))
}
