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
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/version"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"net"
	"os"
	"testing"
	"time"
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

func (s *mockNoopSender) Shutdown() error        { return nil }
func (s *mockNoopSender) SupportsMarkdown() bool { return true }

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

func (s *mockNoneSender) Shutdown() error        { return nil }
func (s *mockNoneSender) SupportsMarkdown() bool { return true }

func makeNoneSender(config alertsender.Config) (alertsender.Sender, error) {
	return &mockNoneSender{}, nil
}

func init() {
	alertsender.Register(alertsender.Noop, makeNoopSender)
	alertsender.Register(alertsender.None, makeNoneSender)
}

func wrapProcessEvent(e *kevent.Kevent, fn func(*kevent.Kevent) (bool, error)) bool {
	match, err := fn(e)
	if err != nil {
		panic(err)
	}
	return match
}

func compileRules(t *testing.T, rules *Rules) {
	stats, err := rules.Compile()
	require.NoError(t, err)
	require.NotNil(t, stats)
}

func fireRules(t *testing.T, c *config.Config) bool {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, c)

	kevt := &kevent.Kevent{
		Type:     ktypes.RecvTCPv4,
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
	compileRules(t, rules)
	return wrapProcessEvent(kevt, rules.ProcessEvent)
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

func TestCompileMergeFilters(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/merged_filters/filter*.yml"))
	compileRules(t, rules)

	assert.Len(t, rules.filters, 2)
	assert.Len(t, rules.filters[ktypes.RecvTCPv4.Hash()], 3)
	assert.Len(t, rules.filters[ktypes.Net.Hash()], 1)

	assert.Len(t, rules.findFilters(&kevent.Kevent{Type: ktypes.RecvUDPv6}), 3)
	assert.Len(t, rules.findFilters(&kevent.Kevent{Type: ktypes.RecvTCPv4}), 3)
	assert.Len(t, rules.findFilters(&kevent.Kevent{Type: ktypes.RecvTCPv4, Category: ktypes.Net}), 4)
}

func TestProcessRules(t *testing.T) {
	var tests = []struct {
		config  *config.Config
		matches bool
	}{
		{newConfig("_fixtures/simple_matches.yml"), true},
		{newConfig("_fixtures/simple_matches/filter*.yml"), true},
	}

	for i, tt := range tests {
		matches := fireRules(t, tt.config)
		if matches != tt.matches {
			t.Errorf("%d. %v process rules mismatch: exp=%t got=%t", i, tt.config.Filters, tt.matches, matches)
		}
	}
}

func TestSequenceState(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_simple.yml"))
	compileRules(t, rules)
	log.SetLevel(log.DebugLevel)

	e1 := &kevent.Kevent{
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
	e2 := &kevent.Kevent{
		Type: ktypes.CreateFile,
		Name: "CreateFile",
		Tid:  2484,
		PID:  4143,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper"},
		},
	}

	assert.Len(t, rules.filters, 2)

	ss := rules.filters[ktypes.CreateProcess.Hash()][0].ss
	ss1 := rules.filters[ktypes.CreateFile.Hash()][0].ss

	// should reference the same sequence state
	assert.Equal(t, ss, ss1)
	require.NotNil(t, ss)

	assert.Equal(t, "kevt.name = CreateProcess AND ps.name = cmd.exe", ss.currentState())
	assert.True(t, ss.isInitialState())
	assert.Equal(t, "kevt.name = CreateProcess AND ps.name = cmd.exe", ss.initialState)

	ss.addPartial("kevt.name = CreateProcess AND ps.name = cmd.exe", e1, false)
	require.NoError(t, ss.matchTransition("kevt.name = CreateProcess AND ps.name = cmd.exe", e1))
	assert.False(t, ss.isInitialState())
	assert.Equal(t, "kevt.name = CreateFile AND file.name ICONTAINS temp", ss.currentState())

	ss.addPartial("kevt.name = CreateFile AND file.name ICONTAINS temp", e2, false)
	require.NoError(t, ss.matchTransition("kevt.name = CreateFile AND file.name ICONTAINS temp", e2))

	assert.Len(t, ss.partials[1], 1)
	assert.Len(t, ss.partials[2], 1)

	assert.Equal(t, sequenceTerminalState, ss.currentState())
	assert.True(t, ss.isTerminalState())

	ss.clear()

	// reset transition leads back to initial state
	assert.Equal(t, "kevt.name = CreateProcess AND ps.name = cmd.exe", ss.currentState())
	// deadline exceeded
	require.NoError(t, ss.matchTransition("kevt.name = CreateProcess AND ps.name = cmd.exe", e1))
	assert.Equal(t, "kevt.name = CreateFile AND file.name ICONTAINS temp", ss.currentState())
	time.Sleep(time.Millisecond * 120)
	assert.True(t, ss.isInitialState())

	require.True(t, ss.inDeadline.Load())
	require.False(t, ss.next(1))
	if ss.next(1) {
		// this shouldn't happen
		require.NoError(t, ss.matchTransition("kevt.name = CreateFile AND file.name ICONTAINS temp", e2))
	}

	ss.clear()
	assert.True(t, ss.isInitialState())
	require.NoError(t, ss.matchTransition("kevt.name = CreateProcess AND ps.name = cmd.exe", e1))
	ss.addPartial("kevt.name = CreateProcess AND ps.name = cmd.exe", e2, false)
	ss.addPartial("kevt.name = CreateFile AND file.name ICONTAINS temp", e2, false)
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
	require.True(t, ss.inExpired.Load())

	require.NoError(t, ss.matchTransition("kevt.name = CreateProcess AND ps.name = cmd.exe", e1))
	require.False(t, ss.inExpired.Load())

	assert.Equal(t, "kevt.name = CreateFile AND file.name ICONTAINS temp", ss.currentState())
}

func TestSequenceStateNext(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_simple.yml"))
	compileRules(t, rules)
	log.SetLevel(log.DebugLevel)

	assert.Len(t, rules.filters, 2)

	ss := rules.filters[ktypes.CreateProcess.Hash()][0].ss

	assert.True(t, ss.next(0))
	assert.False(t, ss.next(1))

	// first rule matched, should be able to proceed
	// to the next rule but can't still reach the third rule
	ss.matchedRules[1] = true
	assert.True(t, ss.next(1))
	assert.False(t, ss.next(2))

	// should be able to reach the third rule
	ss.matchedRules[2] = true
	assert.True(t, ss.next(2))
}

func TestExpireSequences(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_expire.yml"))
	compileRules(t, rules)
	log.SetLevel(log.DebugLevel)

	e1 := &kevent.Kevent{
		Type: ktypes.OpenProcess,
		Name: "OpenProcess",
		Tid:  2484,
		PID:  4143,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.PID, Value: uint32(4143)},
			kparams.DesiredAccess: {Name: kparams.DesiredAccess, Type: kparams.Uint32, Value: uint32(5)},
			kparams.ProcessName:   {Name: kparams.ProcessName, Type: kparams.AnsiString, Value: "powershell.exe"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	e2 := &kevent.Kevent{
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

	ss := rules.filters[ktypes.OpenProcess.Hash()][0].ss

	require.False(t, wrapProcessEvent(e1, rules.ProcessEvent))
	require.False(t, wrapProcessEvent(e2, rules.ProcessEvent))
	require.True(t, ss.inExpired.Load())
}

func TestMinEngineVersion(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/min_engine_version/fail/*.yml"))
	version.Set("2.0.0")
	_, err := rules.Compile()
	require.Error(t, err)
	rules = NewRules(psnap, newConfig("_fixtures/min_engine_version/ok/*.yml"))
	compileRules(t, rules)
}

func TestRuleCompileStats(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/default/*.yml"))
	stats, err := rules.Compile()
	require.NoError(t, err)
	require.NotNil(t, stats)

	assert.True(t, stats.HasImageEvents)
	assert.True(t, stats.HasProcEvents)
	assert.False(t, stats.HasMemEvents)
	assert.False(t, stats.HasAuditAPIEvents)
	assert.True(t, stats.HasDNSEvents)
	assert.Contains(t, stats.UsedEvents, ktypes.CreateProcess)
	assert.Contains(t, stats.UsedEvents, ktypes.LoadImage)
	assert.Contains(t, stats.UsedEvents, ktypes.QueryDNS)
	assert.Contains(t, stats.UsedEvents, ktypes.ConnectTCPv4)
	assert.Contains(t, stats.UsedEvents, ktypes.ConnectTCPv6)
}

func TestSimpleSequenceRule(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_simple.yml"))
	compileRules(t, rules)

	e1 := &kevent.Kevent{
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

	e2 := &kevent.Kevent{
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
	require.False(t, wrapProcessEvent(e1, rules.ProcessEvent))
	require.True(t, wrapProcessEvent(e2, rules.ProcessEvent))

	// if we alter the process executable in the first event, it shouldn't match
	e1.PS.Exe = "C:\\System32\\cmd.exe"

	require.False(t, wrapProcessEvent(e1, rules.ProcessEvent))
	require.False(t, wrapProcessEvent(e2, rules.ProcessEvent))
}

func TestSimpleSequenceRuleMultiplePartials(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_simple_max_span.yml"))
	compileRules(t, rules)

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
		require.False(t, wrapProcessEvent(e, rules.ProcessEvent))
		require.False(t, wrapProcessEvent(e1, rules.ProcessEvent))
	}

	ss := rules.filters[ktypes.CreateProcess.Hash()][0].ss
	assert.Len(t, ss.partials[1], 5)
	assert.Len(t, ss.partials[2], 0)

	e1 := &kevent.Kevent{
		Seq:       20,
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
	e2 := &kevent.Kevent{
		Type:      ktypes.CreateFile,
		Seq:       22,
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
	require.False(t, wrapProcessEvent(e1, rules.ProcessEvent))
	assert.Len(t, ss.partials[1], 6)
	assert.Len(t, ss.partials[2], 0)
	require.True(t, wrapProcessEvent(e2, rules.ProcessEvent))
}

func TestSimpleSequenceRuleWithMaxSpanReached(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_simple_max_span.yml"))
	compileRules(t, rules)

	e1 := &kevent.Kevent{
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

	e2 := &kevent.Kevent{
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
	require.False(t, wrapProcessEvent(e1, rules.ProcessEvent))
	time.Sleep(time.Millisecond * 110)
	require.True(t, wrapProcessEvent(e2, rules.ProcessEvent))

	// now the state machine has transitioned
	// to the initial state, which means we should
	// be able to match the sequence if we reinsert
	// the events
	require.False(t, wrapProcessEvent(e1, rules.ProcessEvent))
	require.True(t, wrapProcessEvent(e2, rules.ProcessEvent))
}

func TestSimpleSequencePolicyWithMaxSpanNotReached(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_simple_max_span.yml"))
	compileRules(t, rules)

	e1 := &kevent.Kevent{
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

	e2 := &kevent.Kevent{
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
	require.False(t, wrapProcessEvent(e1, rules.ProcessEvent))
	time.Sleep(time.Millisecond * 110)
	require.True(t, wrapProcessEvent(e2, rules.ProcessEvent))
}

func TestComplexSequenceRule(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_complex.yml"))
	compileRules(t, rules)
	log.SetLevel(log.DebugLevel)

	e1 := &kevent.Kevent{
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

	e2 := &kevent.Kevent{
		Seq:       2,
		Type:      ktypes.CreateFile,
		Timestamp: time.Now().Add(time.Millisecond * 250),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       2243,
		Category:  ktypes.File,
		PS: &types.PS{
			Name:    "firefox.exe",
			Exe:     "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
			Cmdline: "C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc --channel=\"10464.7.539748228\\1366525930\" -childID 6 -isF",
		},
		Kparams: kevent.Kparams{
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(2), Enum: fs.FileCreateDispositions},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	e3 := &kevent.Kevent{
		Seq:       4,
		Type:      ktypes.ConnectTCPv4,
		Timestamp: time.Now().Add(time.Second),
		Category:  ktypes.Net,
		Name:      "Connect",
		Tid:       244,
		PID:       2243,
		PS: &types.PS{
			Name:    "firefox.exe",
			Exe:     "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
			Cmdline: "C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc --channel=\"10464.7.539748228\\1366525930\" -childID 6 -isF",
		},
		Kparams: kevent.Kparams{
			kparams.NetDIP: {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("10.0.2.3")},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	// register alert sender
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.None}}))

	require.False(t, wrapProcessEvent(e1, rules.ProcessEvent))
	require.False(t, wrapProcessEvent(e2, rules.ProcessEvent))

	ss := rules.filters[ktypes.CreateProcess.Hash()][0].ss
	assert.Len(t, ss.partials[1], 1)
	assert.Len(t, ss.partials[2], 1)

	time.Sleep(time.Millisecond * 30)
	require.True(t, wrapProcessEvent(e3, rules.ProcessEvent))

	time.Sleep(time.Millisecond * 50)

	// check the format of the generated alert
	require.NotNil(t, seqAlert)
	assert.Equal(t, "572902be-76e9-4ee7-a48a-6275fa571cf4", seqAlert.ID)
	assert.Len(t, seqAlert.Events, 3)
	assert.Equal(t, "Phishing dropper outbound communication", seqAlert.Title)
	assert.Equal(t, "firefox.exe process initiated outbound communication to 10.0.2.3", seqAlert.Text)
	seqAlert = nil

	// FSM should transition from terminal to initial state
	require.False(t, wrapProcessEvent(e1, rules.ProcessEvent))
	require.False(t, wrapProcessEvent(e2, rules.ProcessEvent))
	time.Sleep(time.Millisecond * 15)
	require.True(t, wrapProcessEvent(e3, rules.ProcessEvent))
}

func TestSequencePsUUID(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_ps_uuid.yml"))
	compileRules(t, rules)
	log.SetLevel(log.DebugLevel)

	kevt1 := &kevent.Kevent{
		Seq:       1,
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Category:  ktypes.Process,
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       uint32(os.Getpid()),
		PS: &types.PS{
			PID:  uint32(os.Getpid()),
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
		PID:       uint32(os.Getpid()),
		Category:  ktypes.File,
		PS: &types.PS{
			PID:     uint32(os.Getpid()),
			Name:    "firefox.exe",
			Exe:     "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
			Cmdline: "C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc --channel=\"10464.7.539748228\\1366525930\" -childID 6 -isF",
		},
		Kparams: kevent.Kparams{
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(2), Enum: fs.FileCreateDispositions},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	require.False(t, wrapProcessEvent(kevt1, rules.ProcessEvent))
	require.True(t, wrapProcessEvent(kevt2, rules.ProcessEvent))
}

func TestSequenceOutOfOrder(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_out_of_order.yml"))
	compileRules(t, rules)

	now := time.Now()
	e1 := &kevent.Kevent{
		Type:      ktypes.OpenProcess,
		Timestamp: now,
		Name:      "OpenProcess",
		Tid:       2484,
		PID:       859,
		PS: &types.PS{
			PID:  859,
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost-temp.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
			kparams.DesiredAccess: {Name: kparams.DesiredAccess, Type: kparams.Uint32, Value: uint32(5)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	e2 := &kevent.Kevent{
		Type:      ktypes.CreateFile,
		Timestamp: now.Add(time.Millisecond * 200),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &types.PS{
			PID:  859,
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FileName:      {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\lsass.dmp"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(2), Enum: fs.FileCreateDispositions},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	ss := rules.filters[ktypes.CreateFile.Hash()][0].ss

	require.False(t, wrapProcessEvent(e2, rules.ProcessEvent))
	assert.Len(t, ss.partials[2], 1)
	assert.True(t, ss.partials[2][0].ContainsMeta(kevent.RuleSequenceOutOfOrderKey))

	require.True(t, wrapProcessEvent(e1, rules.ProcessEvent))
}

func TestGCSequence(t *testing.T) {
	sequenceGcInterval = time.Millisecond * 300
	maxSequencePartialLifetime = time.Millisecond * 500

	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_gc.yml"))
	compileRules(t, rules)
	log.SetLevel(log.DebugLevel)

	now := time.Now()
	kevt1 := &kevent.Kevent{
		Type:      ktypes.OpenProcess,
		Timestamp: now,
		Name:      "OpenProcess",
		Tid:       2484,
		PID:       859,
		PS: &types.PS{
			PID:  859,
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost-temp.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:     {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
			kparams.DesiredAccess: {Name: kparams.DesiredAccess, Type: kparams.Uint32, Value: uint32(5)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	ss := rules.filters[ktypes.OpenProcess.Hash()][0].ss

	require.False(t, wrapProcessEvent(kevt1, rules.ProcessEvent))

	assert.Len(t, ss.partials[1], 1)

	time.Sleep(time.Second)

	assert.Len(t, ss.partials[1], 0)
}

func TestSequenceAndSimpleRuleMix(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/simple_and_sequence_rules/*.yml"))
	compileRules(t, rules)
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
		Timestamp: time.Now().Add(time.Millisecond * 544),
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
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(2)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	require.True(t, wrapProcessEvent(kevt1, rules.ProcessEvent))
	require.True(t, wrapProcessEvent(kevt2, rules.ProcessEvent))

	kevt3 := &kevent.Kevent{
		Seq:       10,
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now().Add(time.Second * 2),
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

	require.True(t, wrapProcessEvent(kevt3, rules.ProcessEvent))
}

func TestSequenceRuleBoundsFields(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_bound_fields.yml"))
	compileRules(t, rules)

	kevt := &kevent.Kevent{
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost-temp.exe",
			SID:  "zinet",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	kevt1 := &kevent.Kevent{
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now().Add(time.Millisecond * 20),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost-temp.exe",
			SID:  "nusret",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID: {Name: kparams.ProcessID, Type: kparams.Uint32, Value: uint32(4143)},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	kevt2 := &kevent.Kevent{
		Type:      ktypes.CreateFile,
		Timestamp: time.Now().Add(time.Second),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
			SID:  "nusret",
		},
		Kparams: kevent.Kparams{
			kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\system32\\svchost-temp.exe"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	kevt3 := &kevent.Kevent{
		Type:      ktypes.ConnectTCPv4,
		Timestamp: time.Now().Add(time.Second * 3),
		Name:      "Connect",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.File,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost.exe",
			SID:  "zinet",
		},
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(80)},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("172.1.2.3")},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}
	require.False(t, wrapProcessEvent(kevt, rules.ProcessEvent))
	require.False(t, wrapProcessEvent(kevt1, rules.ProcessEvent))
	require.False(t, wrapProcessEvent(kevt2, rules.ProcessEvent))
	require.True(t, wrapProcessEvent(kevt3, rules.ProcessEvent))
}

func TestFilterActionEmitAlert(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.Noop}}))
	rules := NewRules(psnap, newConfig("_fixtures/simple_emit_alert.yml"))
	compileRules(t, rules)

	kevt := &kevent.Kevent{
		Type:     ktypes.RecvTCPv4,
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

	require.True(t, wrapProcessEvent(kevt, rules.ProcessEvent))
	time.Sleep(time.Millisecond * 25)
	require.NotNil(t, emitAlert)
	assert.Equal(t, "match https connections", emitAlert.Title)
	assert.Equal(t, "cmd.exe process received data on port 443", emitAlert.Text)
	assert.Equal(t, alertsender.Critical, emitAlert.Severity)
	assert.Equal(t, []string{"tag1", "tag2"}, emitAlert.Tags)
	emitAlert = nil
}

func TestIsExpressionEvaluable(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_simple.yml"))
	compileRules(t, rules)
	log.SetLevel(log.DebugLevel)

	e1 := &kevent.Kevent{
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

	e2 := &kevent.Kevent{
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

	for _, f := range rules.filters {
		for _, cf := range f {
			e := cf.filter.GetSequence().Expressions[0]
			assert.False(t, e.IsEvaluable(e2))
			assert.True(t, e.IsEvaluable(e1))
		}
	}
}

func TestBoundFieldsWithFunctions(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/sequence_rule_bound_fields_with_functions.yml"))
	compileRules(t, rules)

	kevt1 := &kevent.Kevent{
		Type:     ktypes.CreateFile,
		Name:     "CreateFile",
		Category: ktypes.File,
		Tid:      2484,
		PID:      859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\cmd.exe",
		},
		Kparams: kevent.Kparams{
			kparams.FileName: {Name: kparams.FileName, Type: kparams.UnicodeString, Value: "C:\\Windows\\System32\\passwdflt.dll"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	kevt2 := &kevent.Kevent{
		Type:     ktypes.RegSetValue,
		Name:     "RegSetValue",
		Category: ktypes.Registry,
		Tid:      2484,
		PID:      859,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\cmd.exe",
		},
		Kparams: kevent.Kparams{
			kparams.RegKeyName: {Name: kparams.RegKeyName, Type: kparams.UnicodeString, Value: "HKEY_CURRENT_USER\\Volatile Environment\\Notification Packages"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, "Volatile Environment", registry.SET_VALUE)
	require.NoError(t, err)
	defer key.Close()

	defer func() {
		_ = key.DeleteValue("Notification Packages")
	}()

	require.NoError(t, key.SetStringsValue("Notification Packages", []string{"secli", "passwdflt"}))

	require.False(t, wrapProcessEvent(kevt1, rules.ProcessEvent))
	require.True(t, wrapProcessEvent(kevt2, rules.ProcessEvent))
}

func TestKillAction(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/kill_action.yml"))
	compileRules(t, rules)

	// register alert sender
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.None}}))

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	argv, err := windows.UTF16PtrFromString("calc.exe")
	require.NoError(t, err)
	err = windows.CreateProcess(
		nil,
		argv,
		nil,
		nil,
		true,
		0,
		nil,
		nil,
		&si,
		&pi)
	require.NoError(t, err)

	i := 0
	for !sys.IsProcessRunning(pi.Process) && i < 10 {
		i++
		time.Sleep(time.Millisecond * 100 * time.Duration(i))
	}

	e := &kevent.Kevent{
		Type:      ktypes.CreateProcess,
		Timestamp: time.Now(),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       859,
		Category:  ktypes.Process,
		PS: &types.PS{
			Name: "cmd.exe",
			Exe:  "C:\\Windows\\system32\\svchost-temp.exe",
		},
		Kparams: kevent.Kparams{
			kparams.ProcessID:   {Name: kparams.ProcessID, Type: kparams.PID, Value: pi.ProcessId},
			kparams.ProcessName: {Name: kparams.ProcessName, Type: kparams.UnicodeString, Value: "calc.exe"},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	require.True(t, sys.IsProcessRunning(pi.Process))
	require.True(t, wrapProcessEvent(e, rules.ProcessEvent))
	require.False(t, sys.IsProcessRunning(pi.Process))
}

func BenchmarkRunRules(b *testing.B) {
	b.ReportAllocs()
	psnap := new(ps.SnapshotterMock)
	rules := NewRules(psnap, newConfig("_fixtures/default/*.yml"))
	stats, err := rules.Compile()
	require.NoError(b, err)
	require.NotNil(b, stats)

	b.ResetTimer()
	kevts := []*kevent.Kevent{
		{
			Type:     ktypes.ConnectTCPv4,
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
				kparams.Cmdline:         {Name: kparams.Cmdline, Type: kparams.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
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
			_, _ = rules.ProcessEvent(kevt)
		}
	}
}
