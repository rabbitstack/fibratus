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

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/require"
)

func TestEventSourceConfigLinux(t *testing.T) {
	c := NewWithOpts(WithRun())
	require.NoError(t, c.flags.Parse([]string{
		"--eventsource.enable-process=false",
		"--eventsource.blacklist.events=execve",
		"--eventsource.blacklist.images=systemd",
	}))
	require.NoError(t, c.viper.BindPFlags(c.flags))
	require.NoError(t, c.Init())

	require.False(t, c.EventSource.EnableProcessEvents)
	require.True(t, c.EventSource.ExcludeEvent(event.Execve.ID()))
	require.True(t, c.EventSource.ExcludeImage(&pstypes.PS{Name: "systemd"}))
	for _, typ := range event.All() {
		require.True(t, c.EventSource.EventExists(typ.ID()))
	}
}

func TestValidateLinuxEventSource(t *testing.T) {
	file := filepath.Join(t.TempDir(), "fibratus.yml")
	require.NoError(t, os.WriteFile(file, []byte(`eventsource:
  enable-process: true
  enable-file: true
  blacklist:
    events:
      - execve
      - exit
      - clone
    images:
      - systemd
`), 0o600))

	c := NewWithOpts(WithRun())
	require.NoError(t, c.flags.Parse([]string{"--config-file=" + file}))
	require.NoError(t, c.viper.BindPFlags(c.flags))
	require.NoError(t, c.TryLoadFile(c.GetConfigFile()))
	require.NoError(t, c.Init())
	require.NoError(t, c.Validate())
}
