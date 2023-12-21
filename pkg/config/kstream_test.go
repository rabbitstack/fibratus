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

package config

import (
	"testing"

	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"

	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKstreamConfig(t *testing.T) {
	c := NewWithOpts(WithRun())

	err := c.flags.Parse([]string{
		"--kstream.enable-thread=false",
		"--kstream.enable-registry=false",
		"--kstream.enable-fileio=false",
		"--kstream.enable-net=false",
		"--kstream.enable-image=false",
		"--kstream.blacklist.events=CloseFile,CloseHandle",
		"--kstream.blacklist.images=System,svchost.exe",
	})
	require.NoError(t, err)
	require.NoError(t, c.viper.BindPFlags(c.flags))
	require.NoError(t, err)

	require.NoError(t, c.Init())

	assert.False(t, c.Kstream.EnableThreadKevents)
	assert.False(t, c.Kstream.EnableNetKevents)
	assert.False(t, c.Kstream.EnableRegistryKevents)
	assert.False(t, c.Kstream.EnableImageKevents)
	assert.False(t, c.Kstream.EnableFileIOKevents)

	assert.True(t, c.Kstream.ExcludeKevent(ktypes.CloseHandle))
	assert.False(t, c.Kstream.ExcludeKevent(ktypes.CreateProcess))

	assert.True(t, c.Kstream.ExcludeImage(&pstypes.PS{Name: "svchost.exe"}))
	assert.False(t, c.Kstream.ExcludeImage(&pstypes.PS{Name: "explorer.exe"}))
}
