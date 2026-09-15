//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

	"github.com/stretchr/testify/assert"
)

func TestLinuxEventCatalog(t *testing.T) {
	assert.Equal(t, uint16(1), uint16(Execve))
	assert.Equal(t, uint16(14), uint16(Prctl))
	assert.Equal(t, File, Openat.Category())
	assert.Equal(t, Net, Connect.Category())
	assert.Equal(t, Mem, Mmap.Category())
	assert.Equal(t, Process, Kill.Category())
	assert.Equal(t, "process_vm_readv", ProcessVMRead.String())
	assert.True(t, Openat.Exists())
	for _, typ := range All() {
		assert.True(t, typ.Exists())
		assert.Equal(t, typ, NameToType(typ.String()))
		assert.NotEmpty(t, typ.Description())
		assert.Equal(t, typ.Category(), TypeToEventInfo(typ).Category)
	}
	assert.Equal(t, uint16(Prctl), MaxTypeID())
}

func TestLinuxEventCatalogRejectsWindowsNames(t *testing.T) {
	for _, name := range []string{
		"CreateProcess",
		"TerminateProcess",
		"ProcessRundown",
		"CreateFile",
		"CreateThread",
		"LoadImage",
		"RegOpenKey",
		"RecvTCPv4",
	} {
		assert.Equal(t, UnknownType, NameToType(name), name)
	}
}
