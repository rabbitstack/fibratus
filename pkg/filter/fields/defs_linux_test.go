//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
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

package fields

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/stretchr/testify/require"
)

func TestLinuxFields(t *testing.T) {
	require.True(t, IsField(string(EvtName)))
	require.True(t, IsField(string(PsName)))
	require.True(t, IsField(string(PsParentExe)))
	require.True(t, IsField(string(PsUUID)))
	require.True(t, IsField(string(PsUID)))
	require.True(t, IsField(string(FilePath)))
	require.True(t, IsField(string(FileNewPath)))
	require.True(t, IsField(string(NetDIP)))
	require.True(t, IsField(string(NetFamily)))
	require.True(t, IsField(string(MemBaseAddress)))
	require.True(t, IsField(string(MemFlags)))
	require.True(t, IsField(string(ThreadTID)))
	require.True(t, IsField(string(EvtRetval)))
	require.Equal(t, params.String, EvtName.Type())
	require.Equal(t, params.String, PsName.Type())
	require.Equal(t, params.Uint64, EvtPID.Type())
	require.Equal(t, params.Uint64, EvtTID.Type())
	require.Equal(t, params.Uint64, PsPid.Type())
	require.Equal(t, params.Int64, EvtRetval.Type())
	require.Equal(t, params.IP, NetDIP.Type())
	require.Equal(t, params.Uint32, MemProtection.Type())
}

func TestLinuxExcludesWindowsOnlyFields(t *testing.T) {
	unavailable := []Field{
		KevtPID, KevtTID, KevtSeq, KevtName, KevtArg, KevtCPU, KevtHost,
		PsComm, PsSID, PsDomain, PsIsWOW64Field, PsPeNumSections,
		RegistryPath, PeEntrypoint, HandleName, ImagePath, ModulePath, DllPath,
		DNSName, ThreadpoolPoolID, FileObject, FileOperation, FileIsDLL,
		MemPageType, MemAllocType, MemProtectionMask, ThreadTEB,
		EvtIsDirectSyscall, EvtIsIndirectSyscall,
	}
	for _, field := range unavailable {
		require.False(t, IsField(string(field)), "%s should be unavailable on Linux", field)
	}
}

func TestLinuxKeVtNotDeprecatedBecauseAbsent(t *testing.T) {
	deprecated, d := IsDeprecated(KevtArg)
	require.False(t, deprecated)
	require.Nil(t, d)
}
