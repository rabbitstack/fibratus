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
	"net"
	"os"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
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
	c := &config.Config{
		EventSource: config.EventSourceConfig{
			EnableHandleEvents:   true,
			EnableNetEvents:      true,
			EnableRegistryEvents: true,
			EnableFileIOEvents:   true,
			EnableImageEvents:    true,
			EnableThreadEvents:   true,
		},
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

func wrapProcessEvent(e *event.Event, fn func(*event.Event) (bool, error)) bool {
	match, err := fn(e)
	if err != nil {
		panic(err)
	}
	return match
}

func fireRules(t *testing.T, c *config.Config) bool {
	e := NewEngine(new(ps.SnapshotterMock), c)
	evt := &event.Event{
		Type:     event.RecvTCPv4,
		Name:     "Recv",
		Tid:      2484,
		PID:      859,
		Category: event.Net,
		Params: event.Params{
			params.NetDport: {Name: params.NetDport, Type: params.Uint16, Value: uint16(443)},
			params.NetSport: {Name: params.NetSport, Type: params.Uint16, Value: uint16(43123)},
			params.NetSIP:   {Name: params.NetSIP, Type: params.IPv4, Value: net.ParseIP("127.0.0.1")},
			params.NetDIP:   {Name: params.NetDIP, Type: params.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
		Metadata: make(map[event.MetadataKey]any),
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

	assert.Len(t, e.filters.types, 5)
	assert.Len(t, e.filters.categories, 1)

	var tests = []struct {
		evt   *event.Event
		wants int
	}{
		{&event.Event{Type: event.CreateProcess}, 2},
		{&event.Event{Type: event.RecvUDPv6}, 3},
		{&event.Event{Type: event.RecvTCPv4}, 3},
		{&event.Event{Type: event.RecvTCPv4, Category: event.Net}, 4},
		{&event.Event{Category: event.Net}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.evt.Type.String(), func(t *testing.T) {
			assert.Len(t, e.filters.collect(tt.evt), tt.wants)
		})
	}
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

	e1 := &event.Event{
		Seq:       1,
		Type:      event.CreateProcess,
		Timestamp: time.Now(),
		Category:  event.Process,
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       2243,
		PS: &types.PS{
			Name: "firefox.exe",
			Exe:  "C:\\Program Files\\Firefox\\firefox.exe",
		},
		Params: event.Params{
			params.ProcessID:   {Name: params.ProcessID, Type: params.PID, Value: uint32(2243)},
			params.ProcessName: {Name: params.ProcessName, Type: params.UnicodeString, Value: "firefox.exe"},
		},
		Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	e2 := &event.Event{
		Seq:       2,
		Type:      event.CreateFile,
		Timestamp: time.Now().Add(time.Millisecond * 250),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       2243,
		Category:  event.File,
		PS: &types.PS{
			Name:    "firefox.exe",
			Exe:     "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
			Cmdline: "C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc --channel=\"10464.7.539748228\\1366525930\" -childID 6 -isF",
		},
		Params: event.Params{
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
			params.FileOperation: {Name: params.FileOperation, Type: params.Enum, Value: uint32(2), Enum: fs.FileCreateDispositions},
		},
		Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	e3 := &event.Event{
		Seq:       4,
		Type:      event.ConnectTCPv4,
		Timestamp: time.Now().Add(time.Second),
		Category:  event.Net,
		Name:      "Connect",
		Tid:       244,
		PID:       2243,
		PS: &types.PS{
			Name:    "firefox.exe",
			Exe:     "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
			Cmdline: "C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc --channel=\"10464.7.539748228\\1366525930\" -childID 6 -isF",
		},
		Params: event.Params{
			params.NetDIP: {Name: params.NetDIP, Type: params.IPv4, Value: net.ParseIP("10.0.2.3")},
		},
		Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
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

	e1 := &event.Event{
		Seq:       1,
		Type:      event.CreateProcess,
		Timestamp: time.Now(),
		Category:  event.Process,
		Name:      "CreateProcess",
		Tid:       2243,
		PID:       uint32(os.Getpid()),
		PS: &types.PS{
			PID:  uint32(os.Getpid()),
			Name: "firefox.exe",
			Exe:  "C:\\Program Files\\Firefox\\firefox.exe",
		},
		Params: event.Params{
			params.ProcessID:   {Name: params.ProcessID, Type: params.PID, Value: uint32(os.Getpid())},
			params.ProcessName: {Name: params.ProcessName, Type: params.UnicodeString, Value: "firefox.exe"},
		},
		Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
	}

	e2 := &event.Event{
		Seq:       2,
		Type:      event.CreateFile,
		Timestamp: time.Now(),
		Name:      "CreateFile",
		Tid:       2484,
		PID:       uint32(os.Getpid()),
		Category:  event.File,
		PS: &types.PS{
			PID:     uint32(os.Getpid()),
			Name:    "firefox.exe",
			Exe:     "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
			Cmdline: "C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -contentproc --channel=\"10464.7.539748228\\1366525930\" -childID 6 -isF",
		},
		Params: event.Params{
			params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
			params.FileOperation: {Name: params.FileOperation, Type: params.Enum, Value: uint32(2), Enum: fs.FileCreateDispositions},
		},
		Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
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
	e.RegisterMatchFunc(func(f *config.FilterConfig, evts ...*event.Event) {
		ids := make([]uint64, 0)
		for _, evt := range evts {
			ids = append(ids, evt.Seq)
		}
		expectedMatches[f.Name] = ids
	})

	compileRules(t, e)

	evts := []*event.Event{
		{
			Seq:       1,
			Type:      event.CreateProcess,
			Timestamp: time.Now(),
			Category:  event.Process,
			Name:      "CreateProcess",
			Tid:       2484,
			PID:       2243,
			PS: &types.PS{
				Name: "powershell.exe",
				Exe:  "C:\\Windows\\system32\\powershell.exe",
			},
			Params: event.Params{
				params.ProcessID:   {Name: params.ProcessID, Type: params.PID, Value: uint32(2243)},
				params.ProcessName: {Name: params.ProcessName, Type: params.UnicodeString, Value: "powershell.exe"},
			},
			Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
		},
		{
			Seq:       2,
			Type:      event.CreateFile,
			Timestamp: time.Now().Add(time.Millisecond * 544),
			Name:      "CreateFile",
			Tid:       2484,
			PID:       2243,
			Category:  event.File,
			PS: &types.PS{
				Name: "cmd.exe",
				Exe:  "C:\\Windows\\system32\\cmd.exe",
			},
			Params: event.Params{
				params.FilePath:      {Name: params.FilePath, Type: params.UnicodeString, Value: "C:\\Temp\\dropper.exe"},
				params.FileOperation: {Name: params.FileOperation, Type: params.Enum, Value: uint32(2)},
			},
			Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
		},
		{
			Seq:       10,
			Type:      event.CreateProcess,
			Timestamp: time.Now().Add(time.Second * 2),
			Category:  event.Process,
			Name:      "CreateProcess",
			Tid:       2484,
			PID:       2243,
			PS: &types.PS{
				Name: "chrome.exe",
				Exe:  "C:\\Program Files\\Chrome\\chrome.exe",
				Parent: &types.PS{
					Name: "cmd.exe",
					Exe:  "C:\\Windows\\system32\\cmd.exe",
				},
			},
			Params: event.Params{
				params.ProcessID:   {Name: params.ProcessID, Type: params.PID, Value: uint32(2243)},
				params.ProcessName: {Name: params.ProcessName, Type: params.UnicodeString, Value: "chrome.exe"},
			},
			Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
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
		{"Powershell process spawned", []uint64{1}},
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

	evt := &event.Event{
		Type:     event.RecvTCPv4,
		Name:     "Recv",
		Tid:      2484,
		PID:      859,
		Category: event.Net,
		PS: &types.PS{
			Name: "cmd.exe",
		},
		Params: event.Params{
			params.NetDport: {Name: params.NetDport, Type: params.Uint16, Value: uint16(443)},
			params.NetSport: {Name: params.NetSport, Type: params.Uint16, Value: uint16(43123)},
			params.NetSIP:   {Name: params.NetSIP, Type: params.IPv4, Value: net.ParseIP("127.0.0.1")},
			params.NetDIP:   {Name: params.NetDIP, Type: params.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
		Metadata: make(map[event.MetadataKey]any),
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

	evt := &event.Event{
		Type:      event.CreateProcess,
		Timestamp: time.Now(),
		Name:      "CreateProcess",
		Tid:       2484,
		PID:       pi.ProcessId,
		Category:  event.Process,
		PS: &types.PS{
			Name: "calc.exe",
			Exe:  "C:\\Windows\\system32\\calc.exe",
		},
		Params: event.Params{
			params.ProcessID:   {Name: params.ProcessID, Type: params.PID, Value: pi.ProcessId},
			params.ProcessName: {Name: params.ProcessName, Type: params.UnicodeString, Value: "calc.exe"},
		},
		Metadata: map[event.MetadataKey]any{"foo": "bar", "fooz": "barzz"},
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

	evts := []*event.Event{
		{
			Type:     event.ConnectTCPv4,
			Name:     "Recv",
			Tid:      2484,
			PID:      859,
			Category: event.Net,
			PS: &types.PS{
				Name: "cmd.exe",
			},
			Params: event.Params{
				params.NetDport: {Name: params.NetDport, Type: params.Uint16, Value: uint16(443)},
				params.NetSport: {Name: params.NetSport, Type: params.Uint16, Value: uint16(43123)},
				params.NetSIP:   {Name: params.NetSIP, Type: params.IPv4, Value: net.ParseIP("127.0.0.1")},
				params.NetDIP:   {Name: params.NetDIP, Type: params.IPv4, Value: net.ParseIP("216.58.201.174")},
			},
			Metadata: make(map[event.MetadataKey]any),
		},
		{
			Type:     event.CreateProcess,
			Name:     "CreateProcess",
			Category: event.Process,
			Tid:      2484,
			PID:      859,
			PS: &types.PS{
				Name: "powershell.exe",
			},
			Params: event.Params{
				params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: 2323},
				params.ProcessParentID: {Name: params.ProcessParentID, Type: params.PID, Value: uint32(8390)},
				params.ProcessName:     {Name: params.ProcessName, Type: params.UnicodeString, Value: "spotify.exe"},
				params.Cmdline:         {Name: params.Cmdline, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe --type=crashpad-handler /prefetch:7 --max-uploads=5 --max-db-size=20 --max-db-age=5 --monitor-self-annotation=ptype=crashpad-handler "--metrics-dir=C:\Users\admin\AppData\Local\Spotify\User Data" --url=https://crashdump.spotify.com:443/ --annotation=platform=win32 --annotation=product=spotify --annotation=version=1.1.4.197 --initial-client-data=0x5a4,0x5a0,0x5a8,0x59c,0x5ac,0x6edcbf60,0x6edcbf70,0x6edcbf7c`},
				params.Exe:             {Name: params.Exe, Type: params.UnicodeString, Value: `C:\Users\admin\AppData\Roaming\Spotify\Spotify.exe`},
				params.UserSID:         {Name: params.UserSID, Type: params.UnicodeString, Value: `admin\SYSTEM`},
			},
			Metadata: make(map[event.MetadataKey]any),
		},
		{
			Type:     event.CreateHandle,
			Name:     "CreateHandle",
			Category: event.Handle,
			Tid:      2484,
			PID:      859,
			PS: &types.PS{
				Name: "powershell.exe",
			},
			Params: event.Params{
				params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: 2323},
			},
			Metadata: make(map[event.MetadataKey]any),
		},
	}

	for i := 0; i < b.N; i++ {
		for _, evt := range evts {
			_, _ = e.ProcessEvent(evt)
		}
	}
}
