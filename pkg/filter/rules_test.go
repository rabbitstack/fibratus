/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package filter

import (
	"net"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSender struct{}

var emitAlert *alertsender.Alert

func (s *mockSender) Send(a alertsender.Alert) error {
	emitAlert = &a
	return nil
}

func makeSender(config alertsender.Config) (alertsender.Sender, error) {
	return &mockSender{}, nil
}

func init() {
	alertsender.Register(alertsender.Noop, makeSender)
}

func fireRules(t *testing.T, c *config.Config) bool {
	rules := NewRules(c)

	kevt := &kevent.Kevent{
		Type: ktypes.Recv,
		Name: "Recv",
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
			kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
			kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
		Metadata: make(map[kevent.MetadataKey]string),
	}

	require.NoError(t, rules.Compile())
	return rules.Fire(kevt)
}

func newConfig(fromFiles ...string) *config.Config {
	var kstreamConfig = config.KstreamConfig{
		EnableHandleKevents:   true,
		EnableNetKevents:      true,
		EnableRegistryKevents: true,
		EnableFileIOKevents:   true,
		EnableImageKevents:    true,
		EnableThreadKevents:   true,
	}
	c := &config.Config{
		Kstream: kstreamConfig,
		Filters: &config.Filters{
			Rules: config.Rules{
				FromPaths: fromFiles,
			},
		},
	}
	return c
}

func TestChainCompileMergeGroups(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/merged_groups.yml"))
	require.NoError(t, rules.Compile())

	assert.Len(t, rules.filterGroups, 2)
	assert.Len(t, rules.filterGroups[ktypes.Recv.Hash()], 2)
	assert.Len(t, rules.filterGroups[ktypes.Net.Hash()], 1)

	groups := rules.findFilterGroups(&kevent.Kevent{Type: ktypes.Recv, Category: ktypes.Net})
	assert.Len(t, groups, 3)
}

func TestChainCompileGroupsOnlyTypeSelector(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/groups_type_selector.yml"))
	require.NoError(t, rules.Compile())

	assert.Len(t, rules.filterGroups, 1)
	assert.Len(t, rules.filterGroups[ktypes.Recv.Hash()], 3)

	groups := rules.findFilterGroups(&kevent.Kevent{Type: ktypes.Recv})
	assert.Len(t, groups, 3)
}

func TestFireRules(t *testing.T) {
	var tests = []struct {
		config  *config.Config
		matches bool
	}{
		{newConfig("_fixtures/exclude_policy_or.yml"), false},
		{newConfig("_fixtures/exclude_policy_and.yml"), false},
		{newConfig("_fixtures/exclude_policy_or_no_include_groups.yml"), true},
		{newConfig("_fixtures/exclude_policy_and_no_include_groups.yml"), true},
		{newConfig("_fixtures/exclude_policy_or_different_include_group.yml"), true},
		{newConfig("_fixtures/include_policy_or.yml"), true},
		{newConfig("_fixtures/include_policy_and.yml"), true},
		{newConfig("_fixtures/include_policy_and_not_matches.yml"), false},
	}

	for i, tt := range tests {
		matches := fireRules(t, tt.config)
		if matches != tt.matches {
			t.Errorf("%d. %v filter chain mismatch: exp=%t got=%t", i, tt.config.Filters, tt.matches, matches)
		}
	}
}

func TestIncludeExcludeRemoteThreads(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/include_exclude_remote_threads.yml"))
	require.NoError(t, rules.Compile())

	kevt := &kevent.Kevent{
		Type: ktypes.CreateThread,
		Name: "CreateThread",
		Tid:  2484,
		PID:  859,
		PS: &types.PS{
			Exe: "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
	}

	require.False(t, rules.Fire(kevt))
}

func TestFilterActionEmitAlert(t *testing.T) {
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.Noop}}))
	rules := NewRules(newConfig("_fixtures/include_policy_emit_alert.yml"))
	require.NoError(t, rules.Compile())

	kevt := &kevent.Kevent{
		Type: ktypes.Recv,
		Name: "Recv",
		Tid:  2484,
		PID:  859,
		PS: &types.PS{
			Name: "cmd.exe",
		},
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
			kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
			kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
		Metadata: make(map[kevent.MetadataKey]string),
	}

	require.True(t, rules.Fire(kevt))

	require.NotNil(t, emitAlert)
	assert.Equal(t, "Test alert", emitAlert.Title)
	assert.Equal(t, "cmd.exe process received data on port 443", emitAlert.Text)
	assert.Equal(t, alertsender.Critical, emitAlert.Severity)
	assert.Equal(t, []string{"tag1", "tag2"}, emitAlert.Tags)
}

func BenchmarkChainRun(b *testing.B) {
	b.ReportAllocs()

	rules := NewRules(newConfig("_fixtures/default/default.yml"))
	require.NoError(b, rules.Compile())

	kevts := []*kevent.Kevent{
		{
			Type: ktypes.Connect,
			Name: "Recv",
			Tid:  2484,
			PID:  859,
			PS: &types.PS{
				Name: "cmd.exe",
			},
			Kparams: kevent.Kparams{
				kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
				kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
				kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
				kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
			},
			Metadata: make(map[kevent.MetadataKey]string),
		},
		{
			Type: ktypes.CreateProcess,
			Name: "CreateProcess",
			Tid:  2484,
			PID:  859,
			PS: &types.PS{
				Name: "powershell.exe",
			},
			Kparams: kevent.Kparams{
				kparams.ProcessID:       {Name: kparams.ProcessID, Type: kparams.PID, Value: 2323},
				kparams.ProcessParentID: {Name: kparams.ProcessParentID, Type: kparams.PID, Value: uint32(8390)},
				kparams.ProcessName:     {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "spotify.exe"},
				kparams.Comm:            {Name: kparams.Comm, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
				kparams.Exe:             {Name: kparams.Exe, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
				kparams.UserSID:         {Name: kparams.UserSID, Type: kparams.UnicodeString, Value: `admin\SYSTEM`},
			},
			Metadata: make(map[kevent.MetadataKey]string),
		},
	}

	for i := 0; i < b.N; i++ {
		for _, kevt := range kevts {
			rules.Fire(kevt)
		}
	}
}
