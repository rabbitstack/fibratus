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
	"github.com/rabbitstack/fibratus/pkg/fs"
	log "github.com/sirupsen/logrus"
	"net"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockNoopSender struct{}
type mockNoneSender struct{}

var emitAlert *alertsender.Alert
var seqAlert *alertsender.Alert

func (s *mockNoopSender) Send(a alertsender.Alert) error {
	emitAlert = &a
	return nil
}

func (s *mockNoopSender) Type() alertsender.Type {
	return alertsender.Noop
}

func makeNoopSender(config alertsender.Config) (alertsender.Sender, error) {
	return &mockNoopSender{}, nil
}

func (s *mockNoneSender) Send(a alertsender.Alert) error {
	seqAlert = &a
	return nil
}

func (s *mockNoneSender) Type() alertsender.Type {
	return alertsender.None
}

func makeNoneSender(config alertsender.Config) (alertsender.Sender, error) {
	return &mockNoneSender{}, nil
}

func init() {
	alertsender.Register(alertsender.Noop, makeNoopSender)
	alertsender.Register(alertsender.None, makeNoneSender)
}

func fireRules(t *testing.T, c *config.Config) bool {
	rules := NewRules(c)

	kevt := &kevent.Kevent{
		Type:     ktypes.Recv,
		Name:     "Recv",
		Tid:      2484,
		PID:      859,
		Category: ktypes.Net,
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
			kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
			kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
		Metadata: make(map[kevent.MetadataKey]any),
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

func TestCompileMergeGroups(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/merged_groups.yml"))
	require.NoError(t, rules.Compile())

	assert.Len(t, rules.filterGroups, 2)
	assert.Len(t, rules.filterGroups[ktypes.Recv.Hash()], 2)
	assert.Len(t, rules.filterGroups[ktypes.Net.Hash()], 1)

	groups := rules.findGroups(&kevent.Kevent{Type: ktypes.RecvUDPv6, Category: ktypes.Net})
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

func TestSequenceState(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/sequence_rule_simple.yml"))
	require.NoError(t, rules.Compile())
	log.SetLevel(log.DebugLevel)

	kevt1 := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Name: "CreateProcess",
		Tid:  2484,
		PID:  859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(4143)},
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "powershell.exe"},
		},
	}
	kevt2 := &kevent.Kevent{
		Type: ktypes.CreateFile,
		Name: "CreateFile",
		Tid:  2484,
		PID:  859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper"},
		},
	}

	assert.Len(t, rules.filterGroups, 2)

	ss := rules.filterGroups[ktypes.CreateProcess.Hash()][0].filters[0].ss
	ss1 := rules.filterGroups[ktypes.CreateFile.Hash()][0].filters[0].ss

	// should reference the same sequence state
	assert.Equal(t, ss, ss1)
	require.NotNil(t, ss)

	assert.Equal(t, "kevt.name = CreateProcess AND ps.name = cmd.exe", ss.currentState())
	assert.True(t, ss.isInitialState())
	assert.Equal(t, "kevt.name = CreateProcess AND ps.name = cmd.exe", ss.initialState)

	ss.addPartial("kevt.name = CreateProcess AND ps.name = cmd.exe", kevt1)
	require.NoError(t, ss.matchTransition("kevt.name = CreateProcess AND ps.name = cmd.exe", kevt1))
	assert.False(t, ss.isInitialState())
	assert.Equal(t, "kevt.name = CreateFile AND file.name ICONTAINS temp", ss.currentState())

	ss.addPartial("kevt.name = CreateFile AND file.name ICONTAINS temp", kevt2)
	require.NoError(t, ss.matchTransition("kevt.name = CreateFile AND file.name ICONTAINS temp", kevt2))

	assert.Len(t, ss.partials[1], 1)
	assert.Len(t, ss.partials[2], 1)

	assert.Equal(t, sequenceTerminalState, ss.currentState())
	assert.True(t, ss.isTerminalState())

	ss.clear()

	// reset transition leads back to initial state
	assert.Equal(t, "kevt.name = CreateProcess AND ps.name = cmd.exe", ss.currentState())
	// deadline exceeded
	require.NoError(t, ss.matchTransition("kevt.name = CreateProcess AND ps.name = cmd.exe", kevt1))
	assert.Equal(t, "kevt.name = CreateFile AND file.name ICONTAINS temp", ss.currentState())
	time.Sleep(time.Millisecond * 120)
	assert.True(t, ss.isInitialState())

	require.True(t, ss.inDeadline.Load())
	require.False(t, ss.next(1))
	if ss.next(1) {
		// this shouldn't happen
		require.NoError(t, ss.matchTransition("kevt.name = CreateFile AND file.name ICONTAINS temp", kevt2))
	}

	ss.clear()
	assert.True(t, ss.isInitialState())
	require.NoError(t, ss.matchTransition("kevt.name = CreateProcess AND ps.name = cmd.exe", kevt1))
	ss.addPartial("kevt.name = CreateProcess AND ps.name = cmd.exe", kevt1)
	require.False(t, ss.inDeadline.Load())

	// test expiration
	terminateProcess := &kevent.Kevent{
		Type: ktypes.TerminateProcess,
		Name: "TerminateProcess",
		Tid:  2484,
		PID:  859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(4143)},
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "powershell.exe"},
		},
	}

	require.True(t, ss.expire(terminateProcess))
	require.True(t, ss.inExpired)

	require.NoError(t, ss.matchTransition("kevt.name = CreateProcess AND ps.name = cmd.exe", kevt1))
	require.False(t, ss.inExpired)

	assert.Equal(t, "kevt.name = CreateFile AND file.name ICONTAINS temp", ss.currentState())
}

func TestSimpleSequenceRule(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/sequence_rule_simple.yml"))
	require.NoError(t, rules.Compile())

	kevt1 := &kevent.Kevent{
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost-temp.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	kevt2 := &kevent.Kevent{
		Type:      ktypes.CreateFile,
		Timestamp: time.Now(),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-temp.exe"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	require.False(t, rules.Fire(kevt1))
	require.True(t, rules.Fire(kevt2))

	// if we alter the process executable in the first event, it shouldn't match
	kevt1.PS.Exe = "C:\\System32\\cmd.exe"

	require.False(t, rules.Fire(kevt1))
	require.False(t, rules.Fire(kevt2))
}

func TestSimpleSequenceRuleMultiplePartials(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/sequence_rule_simple_max_span.yml"))
	require.NoError(t, rules.Compile())

	// create random matches which don't satisfy the BY statement
	for i, pid := range []uint32{2343, 1024, 11122, 3450, 12319} {
		e := &kevent.Kevent{
			Type:      ktypes.CreateProcess,
			Timestamp: time.Now().Add(time.Duration(i) * time.Millisecond),
			Name:      "CreateProcess",
			Tid:       2484,
			PID:       pid,
			PS: &types.PS{
				Name: "cmd.exe",
				Exe:  "C:\\Windows\\system32\\cmd.exe",
			},
			Kparams: kevent.Kparams{
				kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: pid % 2},
			},
			Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
		}
		e1 := &kevent.Kevent{
			Type:      ktypes.CreateFile,
			Timestamp: time.Now().Add(time.Duration(i) * time.Millisecond * 2),
			Name:      "CreateFile",
			Tid:       2484,
			PID:       pid * 2,
			Category:  ktypes.File,
			PS: &types.PS{
				Name: "cmd.exe",
				Exe:  "C:\\Windows\\system32\\cmd.exe",
			},
			Kparams: kevent.Kparams{
				kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-temp.exe"},
			},
			Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
		}
		require.False(t, rules.Fire(e))
		require.False(t, rules.Fire(e1))
	}

	ss := rules.filterGroups[ktypes.CreateProcess.Hash()][0].filters[0].ss
	assert.Len(t, ss.partials[1], 5)
	assert.Len(t, ss.partials[2], 5)

	kevt1 := &kevent.Kevent{
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now().Add(time.Second),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost-temp.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	kevt2 := &kevent.Kevent{
		Type:      ktypes.CreateFile,
		Timestamp: time.Now().Add(time.Second * time.Duration(2)),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-temp.exe"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	require.False(t, rules.Fire(kevt1))
	require.True(t, rules.Fire(kevt2))
}

func TestSimpleSequenceRuleWithMaxSpanReached(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/sequence_rule_simple_max_span.yml"))
	require.NoError(t, rules.Compile())

	kevt1 := &kevent.Kevent{
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	kevt2 := &kevent.Kevent{
		Type:      ktypes.CreateFile,
		Timestamp: time.Now(),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	require.False(t, rules.Fire(kevt1))
	time.Sleep(time.Millisecond * 250)
	require.False(t, rules.Fire(kevt2))

	// now the state machine has transitioned
	// to the initial state, which means we should
	// be able to match the sequence if we reinsert
	// the events
	require.False(t, rules.Fire(kevt1))
	require.True(t, rules.Fire(kevt2))
}

func TestSimpleSequencePolicyWithMaxSpanNotReached(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/sequence_rule_simple_max_span.yml"))
	require.NoError(t, rules.Compile())

	kevt1 := &kevent.Kevent{
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	kevt2 := &kevent.Kevent{
		Type:      ktypes.CreateFile,
		Timestamp: time.Now(),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	require.False(t, rules.Fire(kevt1))
	time.Sleep(time.Millisecond * 110)
	require.True(t, rules.Fire(kevt2))
}

func TestComplexSequenceRule(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/sequence_rule_complex.yml"))
	require.NoError(t, rules.Compile())
	log.SetLevel(log.DebugLevel)

	kevt1 := &kevent.Kevent{
		Seq:       1,
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Category:  ktypes.Process,
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &types.PS{
			Name: "explorer.exe",
			Exe:  "C:\\Windows\\system32\\explorer.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(2243)},
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "firefox.exe"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	kevt2 := &kevent.Kevent{
		Seq:       2,
		Type:      ktypes.CreateFile,
		Timestamp: time.Now(),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       2243,
		Category:  ktypes.File,
		PS: &types.PS{
			Name: "firefox.exe",
			Exe:  "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
			Comm: "C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc --channel=\"10464.7.539748228\\1366525930\" -childID 6 -isF",
		},
		Kparams: kevent.Kparams{
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: fs.FileDisposition(2)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	kevt3 := &kevent.Kevent{
		Seq:       4,
		Type:      ktypes.Connect,
		Timestamp: time.Now(),
		Category:  ktypes.Net,
		Name:      "Connect",
		Tid:       244,
		PID:       2243,
		PS: &types.PS{
			Name: "firefox.exe",
			Exe:  "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
			Comm: "C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc --channel=\"10464.7.539748228\\1366525930\" -childID 6 -isF",
		},
		Kparams: kevent.Kparams{
			kparams.NetDIP: {Name: kparams.NetDIP, Type: kparams.IP, Value: net.ParseIP("10.0.2.3")},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	// register alert sender
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.None}}))

	require.False(t, rules.Fire(kevt1))
	require.False(t, rules.Fire(kevt2))
	time.Sleep(time.Millisecond * 30)
	require.True(t, rules.Fire(kevt3))

	time.Sleep(time.Millisecond * 50)

	// check the format of the generated alert
	require.NotNil(t, seqAlert)
	assert.Equal(t, "Phishing dropper outbound communication", seqAlert.Title)
	assert.Equal(t, "firefox.exe process initiated outbound communication to 10.0.2.3", seqAlert.Text)
	seqAlert = nil

	// FSM should transition from terminal to initial state
	require.False(t, rules.Fire(kevt1))
	require.False(t, rules.Fire(kevt2))
	time.Sleep(time.Millisecond * 15)
	require.True(t, rules.Fire(kevt3))
}

func TestSequenceAndSimpleRuleMix(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/sequence_and_simple_rule_mix.yml"))
	require.NoError(t, rules.Compile())
	log.SetLevel(log.DebugLevel)

	kevt1 := &kevent.Kevent{
		Seq:       1,
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Category:  ktypes.Process,
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       2243,
		PS: &types.PS{
			Name: "powershell.exe",
			Exe:  "C:\\Windows\\system32\\powershell.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(2243)},
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "firefox.exe"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	kevt2 := &kevent.Kevent{
		Seq:       2,
		Type:      ktypes.CreateFile,
		Timestamp: time.Now(),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       2243,
		Category:  ktypes.File,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\cmd.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: fs.FileDisposition(2)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	require.True(t, rules.Fire(kevt1))
	require.True(t, rules.Fire(kevt2))

	kevt3 := &kevent.Kevent{
		Seq:       10,
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Category:  ktypes.Process,
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       2243,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\cmd.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(2243)},
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "chrome.exe"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	require.True(t, rules.Fire(kevt3))
}

func TestFilterActionEmitAlert(t *testing.T) {
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.Noop}}))
	rules := NewRules(newConfig("_fixtures/include_policy_emit_alert.yml"))
	require.NoError(t, rules.Compile())

	kevt := &kevent.Kevent{
		Type:     ktypes.Recv,
		Name:     "Recv",
		Tid:      2484,
		PID:      859,
		Category: ktypes.Net,
		PS: &types.PS{
			Name: "cmd.exe",
		},
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
			kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
			kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
		Metadata: make(map[kevent.MetadataKey]any),
	}

	require.True(t, rules.Fire(kevt))
	time.Sleep(time.Millisecond * 25)
	require.NotNil(t, emitAlert)
	assert.Equal(t, "Test alert", emitAlert.Title)
	assert.Equal(t, "cmd.exe process received data on port 443", emitAlert.Text)
	assert.Equal(t, alertsender.Critical, emitAlert.Severity)
	assert.Equal(t, []string{"tag1", "tag2"}, emitAlert.Tags)
	emitAlert = nil
}

func TestIsKtypeEligible(t *testing.T) {
	rules := NewRules(newConfig("_fixtures/sequence_rule_simple.yml"))
	require.NoError(t, rules.Compile())
	log.SetLevel(log.DebugLevel)

	kevt1 := &kevent.Kevent{
		Type: ktypes.CreateProcess,
		Name: "CreateProcess",
		Tid:  2484,
		PID:  859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	kevt2 := &kevent.Kevent{
		Type: ktypes.RenameFile,
		Name: "RenameFile",
		Tid:  2484,
		PID:  859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	for _, groups := range rules.filterGroups {
		for _, g := range groups {
			for _, f := range g.filters {
				assert.False(t, f.isEligible(kevt2))
				assert.True(t, f.isEligible(kevt1))
			}
		}
	}
}

func BenchmarkRunRules(b *testing.B) {
	b.ReportAllocs()

	rules := NewRules(newConfig("_fixtures/default/default.yml"))
	require.NoError(b, rules.Compile())

	b.ResetTimer()
	kevts := []*kevent.Kevent{
		{
			Type:     ktypes.Connect,
			Name:     "Recv",
			Tid:      2484,
			PID:      859,
			Category: ktypes.Net,
			PS: &types.PS{
				Name: "cmd.exe",
			},
			Kparams: kevent.Kparams{
				kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
				kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
				kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
				kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
			},
			Metadata: make(map[kevent.MetadataKey]any),
		},
		{
			Type:     ktypes.CreateProcess,
			Name:     "CreateProcess",
			Category: ktypes.Process,
			Tid:      2484,
			PID:      859,
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
			Metadata: make(map[kevent.MetadataKey]any),
		},
		{
			Type:     ktypes.CreateHandle,
			Name:     "CreateHandle",
			Category: ktypes.Handle,
			Tid:      2484,
			PID:      859,
			PS: &types.PS{
				Name: "powershell.exe",
			},
			Kparams: kevent.Kparams{
				kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.PID, Value: 2323},
			},
			Metadata: make(map[kevent.MetadataKey]any),
		},
	}

	for i := 0; i < b.N; i++ {
		for _, kevt := range kevts {
			rules.Fire(kevt)
		}
	}
}
