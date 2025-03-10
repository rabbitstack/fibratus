/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package rules

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
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
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

func compileRules(t *testing.T, e *Engine) {
	rs, err := e.Compile()
	require.NoError(t, err)
	require.NotNil(t, rs)
}

func wrapProcessEvent(e *kevent.Kevent, fn func(*kevent.Kevent) (bool, error)) bool {
	match, err := fn(e)
	if err != nil {
		panic(err)
	}
	return match
}

func fireRules(t *testing.T, c *config.Config) bool {
	e := NewEngine(new(ps.SnapshotterMock), c)
	evt := &kevent.Kevent{
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
	compileRules(t, e)
	return wrapProcessEvent(evt, e.ProcessEvent)
}

func TestCompileIndexableFilters(t *testing.T) {
	e := NewEngine(new(ps.SnapshotterMock), newConfig(
		"_fixtures/merged_filters/filter*.yml",
		"_fixtures/default/microsoft_edge.yml",
		"_fixtures/default/windows_error_*.yml"))

	compileRules(t, e)

	assert.Len(t, e.filters, 3)

	var tests = []struct {
		evt   *kevent.Kevent
		wants int
	}{
		{&kevent.Kevent{Type: ktypes.CreateProcess}, 2},
		{&kevent.Kevent{Type: ktypes.RecvUDPv6}, 3},
		{&kevent.Kevent{Type: ktypes.RecvTCPv4}, 3},
		{&kevent.Kevent{Type: ktypes.RecvTCPv4, Category: ktypes.Net}, 4},
		{&kevent.Kevent{Category: ktypes.Net}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.evt.Type.String(), func(t *testing.T) {
			assert.Len(t, e.filters.collect(e.hashCache, tt.evt), tt.wants)
		})
	}

	assert.Len(t, e.hashCache.types, 4)

	evt := &kevent.Kevent{Type: ktypes.RecvTCPv4}

	h1, h2 := e.hashCache.typeHash(evt), e.hashCache.categoryHash(evt)
	assert.Equal(t, uint32(0xfa4dab59), h1)
	assert.Equal(t, uint32(0x811c9dc5), h2)
}

func TestRunSimpleRules(t *testing.T) {
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

func TestRunSequenceRule(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	e := NewEngine(new(ps.SnapshotterMock), newConfig("_fixtures/sequence_rule_complex.yml"))
	compileRules(t, e)

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
			kparams.FilePath:      {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
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

	require.False(t, wrapProcessEvent(e1, e.ProcessEvent))
	require.False(t, wrapProcessEvent(e2, e.ProcessEvent))

	time.Sleep(time.Millisecond * 30)
	require.True(t, wrapProcessEvent(e3, e.ProcessEvent))

	time.Sleep(time.Millisecond * 50)

	// check the format of the generated alert
	require.NotNil(t, seqAlert)
	assert.Equal(t, "572902be-76e9-4ee7-a48a-6275fa571cf4", seqAlert.ID)
	assert.Len(t, seqAlert.Events, 3)
	assert.Equal(t, "Phishing dropper outbound communication", seqAlert.Title)
	assert.Equal(t, "firefox.exe process initiated outbound communication to 10.0.2.3", seqAlert.Text)
	seqAlert = nil

	// FSM should transition from terminal to initial state
	require.False(t, wrapProcessEvent(e1, e.ProcessEvent))
	require.False(t, wrapProcessEvent(e2, e.ProcessEvent))
	time.Sleep(time.Millisecond * 15)
	require.True(t, wrapProcessEvent(e3, e.ProcessEvent))
}

func TestRunSequenceRuleWithPsUUIDLink(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	e := NewEngine(new(ps.SnapshotterMock), newConfig("_fixtures/sequence_rule_ps_uuid.yml"))
	compileRules(t, e)

	e1 := &kevent.Kevent{
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

	e2 := &kevent.Kevent{
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
			kparams.FilePath:      {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
			kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(2), Enum: fs.FileCreateDispositions},
		},
		Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	require.False(t, wrapProcessEvent(e1, e.ProcessEvent))
	require.True(t, wrapProcessEvent(e2, e.ProcessEvent))
}

func TestRunSimpleAndSequenceRules(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	expectedMatches := make(map[string][]uint64)
	c := newConfig("_fixtures/simple_and_sequence_rules/*.yml")
	c.Filters.MatchAll = true
	e := NewEngine(new(ps.SnapshotterMock), c)
	e.RegisterMatchFunc(func(f *config.FilterConfig, evts ...*kevent.Kevent) {
		ids := make([]uint64, 0)
		for _, evt := range evts {
			ids = append(ids, evt.Seq)
		}
		expectedMatches[f.Name] = ids
	})

	compileRules(t, e)

	evts := []*kevent.Kevent{
		{
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
		},
		{
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
				kparams.FilePath:      {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
				kparams.FileOperation: {Name: kparams.FileOperation, Type: kparams.Enum, Value: uint32(2)},
			},
			Metadata: map[kevent.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
		},
		{
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
		},
	}

	for _, evt := range evts {
		require.True(t, wrapProcessEvent(evt, e.ProcessEvent))
	}

	assert.Len(t, expectedMatches, 4)

	var tests = []struct {
		rule     string
		eventIDs []uint64
	}{
		{"Process spawned by powershell", []uint64{1}},
		{"Powershell created a temp file", []uint64{1, 2}},
		{"Spawn Chrome browser", []uint64{10}},
		{"Command shell spawned Chrome browser", []uint64{1, 10}},
	}

	for _, tt := range tests {
		t.Run(tt.rule, func(t *testing.T) {
			assert.Equal(t, expectedMatches[tt.rule], tt.eventIDs)
		})
	}
}

func TestAlertAction(t *testing.T) {
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.Noop}}))
	e := NewEngine(new(ps.SnapshotterMock), newConfig("_fixtures/simple_emit_alert.yml"))
	compileRules(t, e)

	evt := &kevent.Kevent{
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

	require.True(t, wrapProcessEvent(evt, e.ProcessEvent))
	time.Sleep(time.Millisecond * 25)
	require.NotNil(t, emitAlert)
	assert.Equal(t, "match https connections", emitAlert.Title)
	assert.Equal(t, "cmd.exe process received data on port 443", emitAlert.Text)
	assert.Equal(t, alertsender.Critical, emitAlert.Severity)
	assert.Equal(t, []string{"tag1", "tag2"}, emitAlert.Tags)
	emitAlert = nil
}

func TestKillAction(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	e := NewEngine(new(ps.SnapshotterMock), newConfig("_fixtures/kill_action.yml"))
	compileRules(t, e)

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

	evt := &kevent.Kevent{
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
	require.True(t, wrapProcessEvent(evt, e.ProcessEvent))
	require.False(t, sys.IsProcessRunning(pi.Process))
}

func BenchmarkRunRules(b *testing.B) {
	b.ReportAllocs()
	e := NewEngine(new(ps.SnapshotterMock), newConfig("_fixtures/default/*.yml"))
	rs, err := e.Compile()
	require.NoError(b, err)
	require.NotNil(b, rs)

	b.ResetTimer()

	evts := []*kevent.Kevent{
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
		for _, evt := range evts {
			_, _ = e.ProcessEvent(evt)
		}
	}
}
