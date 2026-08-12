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
	require.Equal(t, params.String, EvtName.Type())
	require.Equal(t, params.String, PsName.Type())
	require.Equal(t, params.Uint64, EvtPID.Type())
	require.Equal(t, params.Uint64, EvtTID.Type())
	require.Equal(t, params.Uint64, PsPid.Type())
	require.False(t, IsField(string(KevtPID)))
	require.False(t, IsField(string(KevtTID)))
	require.False(t, IsField(string(PsComm)))
	require.False(t, IsField(string(RegistryPath)))
	require.False(t, IsField(string(PeEntrypoint)))
}
