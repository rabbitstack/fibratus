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
	"github.com/rabbitstack/fibratus/pkg/event"
	"testing"

	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEventSourceConfig(t *testing.T) {
	c := NewWithOpts(WithRun())

	err := c.flags.Parse([]string{
		"--eventsource.enable-thread=false",
		"--eventsource.enable-registry=false",
		"--eventsource.enable-fileio=false",
		"--eventsource.enable-net=false",
		"--eventsource.enable-image=false",
		"--eventsource.blacklist.events=CloseFile,CloseHandle",
		"--eventsource.blacklist.images=System,svchost.exe",
	})
	require.NoError(t, err)
	require.NoError(t, c.viper.BindPFlags(c.flags))
	require.NoError(t, err)

	require.NoError(t, c.Init())

	assert.False(t, c.EventSource.EnableThreadEvents)
	assert.False(t, c.EventSource.EnableNetEvents)
	assert.False(t, c.EventSource.EnableRegistryEvents)
	assert.False(t, c.EventSource.EnableImageEvents)
	assert.False(t, c.EventSource.EnableFileIOEvents)

	assert.True(t, c.EventSource.ExcludeEvent(event.CloseHandle.GUID(), event.CloseHandle.HookID()))
	assert.False(t, c.EventSource.ExcludeEvent(event.CreateProcess.GUID(), event.CreateProcess.HookID()))

	assert.True(t, c.EventSource.ExcludeImage(&pstypes.PS{Name: "svchost.exe"}))
	assert.False(t, c.EventSource.ExcludeImage(&pstypes.PS{Name: "explorer.exe"}))
}
