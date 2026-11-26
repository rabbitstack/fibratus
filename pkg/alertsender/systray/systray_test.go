//go:build windows

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package systray

import (
	"io"
	"strings"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	yconfig "github.com/rabbitstack/fibratus/pkg/yara/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// newSender loads the systray sender without starting the helper
// process, since the test binary would end up launching itself.
func newSender(t *testing.T, c Config) alertsender.Sender {
	t.Helper()

	launchHelper = func() (windows.Handle, error) { return 0, nil }
	t.Cleanup(func() { launchHelper = startHelper })

	s, err := alertsender.Load(alertsender.Config{Type: alertsender.Systray, Sender: c})
	require.NoError(t, err)
	require.NotNil(t, s)
	t.Cleanup(func() { _ = s.Shutdown() })

	return s
}

func TestSystraySender(t *testing.T) {
	s := newSender(t, Config{Enabled: true, Sound: true, QuietMode: true})

	c, err := Dial()
	require.NoError(t, err)
	defer c.Close()

	// the settings are always the first message
	m, err := c.Recv()
	require.NoError(t, err)
	require.Equal(t, Conf, m.Type)
	var settings Settings
	require.NoError(t, m.Decode(&settings))
	assert.True(t, settings.Sound)
	assert.True(t, settings.QuietMode)

	require.NoError(t, s.Send(alertsender.Alert{
		Title: "LSASS memory dumping via legitimate or offensive tools",
		Text: `Detected an attempt by mimikatz.exe process to access and read
	the memory of the Local Security And Authority Subsystem Service
	and subsequently write the C:\\temp\lsass.dmp dump file to the disk device`,
		Labels: map[string]string{"secret": "must not cross the pipe"},
	}))

	m, err = c.Recv()
	require.NoError(t, err)
	require.Equal(t, Balloon, m.Type)
	assert.NotContains(t, string(m.Data), "secret")
	var n Notification
	require.NoError(t, m.Decode(&n))
	assert.Equal(t, defaultTitle, n.Title)
	assert.Equal(t, "LSASS memory dumping via legitimate or offensive tools", n.Text)
}

func TestSystraySenderMultipleClients(t *testing.T) {
	s := newSender(t, Config{Enabled: true})

	c1, err := Dial()
	require.NoError(t, err)
	defer c1.Close()
	c2, err := Dial()
	require.NoError(t, err)
	defer c2.Close()

	for _, c := range []*Client{c1, c2} {
		m, err := c.Recv()
		require.NoError(t, err)
		require.Equal(t, Conf, m.Type)
	}

	require.NoError(t, s.Send(alertsender.Alert{Title: "Suspicious activity"}))

	for _, c := range []*Client{c1, c2} {
		m, err := c.Recv()
		require.NoError(t, err)
		require.Equal(t, Balloon, m.Type)
	}

	// the sender keeps working after a client leaves
	require.NoError(t, c1.Close())
	require.NoError(t, s.Send(alertsender.Alert{Title: "Suspicious activity"}))
	m, err := c2.Recv()
	require.NoError(t, err)
	require.Equal(t, Balloon, m.Type)
}

func TestSystraySenderNoClients(t *testing.T) {
	s := newSender(t, Config{Enabled: true})

	// nobody is logged in, which is fine
	require.NoError(t, s.Send(alertsender.Alert{Title: "Suspicious activity"}))
}

func TestSystraySenderShutdownClosesClients(t *testing.T) {
	s := newSender(t, Config{Enabled: true})

	c, err := Dial()
	require.NoError(t, err)
	defer c.Close()
	_, err = c.Recv()
	require.NoError(t, err)

	require.NoError(t, s.Shutdown())

	_, err = c.Recv()
	require.ErrorIs(t, err, io.EOF)

	// shutting down twice is harmless
	require.NoError(t, s.Shutdown())
}

func TestSystraySenderPipeInUse(t *testing.T) {
	_ = newSender(t, Config{Enabled: true})

	// The pipe is already served by the first sender. The second one must
	// not fail the whole alert sender initialization, and it must not
	// take over the pipe either
	s2 := newSender(t, Config{Enabled: true})
	require.NoError(t, s2.Send(alertsender.Alert{Title: "Suspicious activity"}))
	require.NoError(t, s2.Shutdown())

	c, err := Dial()
	require.NoError(t, err)
	defer c.Close()
}

func TestSystraySenderDisabled(t *testing.T) {
	s := newSender(t, Config{Enabled: false})

	_, err := Dial()
	require.Error(t, err)

	require.NoError(t, s.Send(alertsender.Alert{Title: "Suspicious activity"}))
	require.NoError(t, s.Shutdown())
}

func TestNotification(t *testing.T) {
	var tests = []struct {
		name  string
		alert alertsender.Alert
		want  Notification
	}{
		{
			"rule alert gets the generic title",
			alertsender.Alert{Title: "Suspicious DLL loading", Text: "details that are not shown"},
			Notification{Title: defaultTitle, Text: "Suspicious DLL loading"},
		},
		{
			"memory threat alert keeps title and text",
			alertsender.Alert{Title: yconfig.MemoryThreatAlertTitle, Text: "Mimikatz found in memory"},
			Notification{Title: yconfig.MemoryThreatAlertTitle, Text: "Mimikatz found in memory"},
		},
		{
			"file threat alert keeps title and text",
			alertsender.Alert{Title: yconfig.FileThreatAlertTitle, Text: "Ransomware dropped on disk"},
			Notification{Title: yconfig.FileThreatAlertTitle, Text: "Ransomware dropped on disk"},
		},
		{
			"long text is truncated",
			alertsender.Alert{Title: yconfig.FileThreatAlertTitle, Text: strings.Repeat("ž", maxTextLen*2)},
			Notification{Title: yconfig.FileThreatAlertTitle, Text: strings.Repeat("ž", maxTextLen)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, notification(tt.alert))
		})
	}
}

func TestEncodeMsg(t *testing.T) {
	b, err := encodeMsg(Balloon, Notification{Title: "a\nb", Text: "line1\r\nline2"})
	require.NoError(t, err)

	// exactly one frame terminator, even if the text contains line breaks
	assert.Equal(t, 1, strings.Count(string(b), "\n"))
	assert.True(t, strings.HasSuffix(string(b), "\n"))

	_, err = encodeMsg(Balloon, Notification{Text: strings.Repeat("a", maxMsgSize)})
	require.Error(t, err)
}
