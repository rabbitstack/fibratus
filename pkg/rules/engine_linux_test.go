//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
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
	"path/filepath"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockNoneSender struct{}

func (s *mockNoneSender) Send(alertsender.Alert) error { return nil }
func (s *mockNoneSender) Type() alertsender.Type       { return alertsender.None }
func (s *mockNoneSender) Shutdown() error              { return nil }
func (s *mockNoneSender) SupportsMarkdown() bool       { return true }

func makeNoneSender(alertsender.Config) (alertsender.Sender, error) {
	return &mockNoneSender{}, nil
}

func init() {
	alertsender.Register(alertsender.None, makeNoneSender)
}

func newLinuxConfig(fromFiles ...string) *config.Config {
	return &config.Config{
		EventSource: config.EventSourceConfig{
			EnableFileIOEvents: true,
			EnableNetEvents:    true,
			EnableMemEvents:    true,
		},
		Filters: &config.Filters{
			Rules: config.Rules{
				FromPaths: fromFiles,
			},
			Macros: config.Macros{
				FromPaths: []string{filepath.Join("..", "..", "rules", "linux", "macros", "*")},
			},
		},
	}
}

func compileRules(t *testing.T, e *Engine) *config.RulesCompileResult {
	t.Helper()
	rs, err := e.Compile()
	require.NoError(t, err)
	require.NotNil(t, rs)
	return rs
}

func processEvent(t *testing.T, e *Engine, evt *event.Event) bool {
	t.Helper()
	match, err := e.ProcessEvent(evt)
	require.NoError(t, err)
	return match
}

func testPS(name, exe string, pid uint64, start uint64) *pstypes.PS {
	return &pstypes.PS{
		PID:           pid,
		Ppid:          1,
		Name:          name,
		Cmdline:       exe,
		Exe:           exe,
		StartBootTime: start,
		Parent:        &pstypes.PS{PID: 1, Name: "systemd", StartBootTime: 1},
	}
}

func TestNewEngineAcceptsSnapshotter(t *testing.T) {
	cfg := &config.Config{Filters: &config.Filters{}}
	e := NewEngine(ps.NewSnapshotter(), cfg)
	require.NotNil(t, e)
	require.NotNil(t, e.compiler)
}

func TestCompileIndexesLinuxTypesAndCategories(t *testing.T) {
	e := NewEngine(ps.NewSnapshotter(), newLinuxConfig(
		filepath.Join("..", "..", "rules", "linux", "*.yml"),
		"_fixtures/shared/*.yml",
	))
	rs := compileRules(t, e)

	require.True(t, rs.HasProcEvents)
	require.True(t, rs.HasNetworkEvents)
	assert.Contains(t, rs.UsedEvents, event.Execve)
	assert.Contains(t, rs.UsedEvents, event.Ptrace)
	assert.Contains(t, rs.UsedEvents, event.Kill)
	assert.Contains(t, rs.UsedEvents, event.Connect)

	assert.NotEmpty(t, e.filters.types[event.Execve])
	assert.NotEmpty(t, e.filters.types[event.Ptrace])
	assert.NotEmpty(t, e.filters.types[event.Kill])
	assert.NotEmpty(t, e.filters.types[event.Connect])
	assert.NotEmpty(t, e.filters.categories[event.Process.Index()])
	assert.NotEmpty(t, e.filters.categories[event.Net.Index()])
}

func TestRunLinuxDetectionRules(t *testing.T) {
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.None}}))

	e := NewEngine(ps.NewSnapshotter(), newLinuxConfig(filepath.Join("..", "..", "rules", "linux", "*.yml")))
	compileRules(t, e)

	tmpPS := testPS("dropper", "/tmp/dropper", 4242, 200)
	execTmp := &event.Event{
		Type:      event.Execve,
		Name:      "execve",
		Category:  event.Process,
		PID:       4242,
		Timestamp: time.Now(),
		PS:        tmpPS,
		Params: event.Params{
			params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint64(4242)},
			params.Exe:       {Name: params.Exe, Type: params.Path, Value: "/tmp/dropper"},
			params.Retval:    {Name: params.Retval, Type: params.Int64, Value: int64(0)},
		},
		Metadata: make(map[event.MetadataKey]any),
	}
	require.True(t, processEvent(t, e, execTmp))

	ptrace := &event.Event{
		Type:      event.Ptrace,
		Name:      "ptrace",
		Category:  event.Process,
		PID:       4242,
		Timestamp: time.Now(),
		PS:        testPS("injector", "/usr/bin/injector", 4242, 200),
		Params: event.Params{
			params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint64(4242)},
			params.PtraceRequest:   {Name: params.PtraceRequest, Type: params.Int64, Value: int64(16)},
			params.TargetProcessID: {Name: params.TargetProcessID, Type: params.PID, Value: uint64(99)},
		},
		Metadata: make(map[event.MetadataKey]any),
	}
	require.True(t, processEvent(t, e, ptrace))

	sigkill := &event.Event{
		Type:      event.Kill,
		Name:      "kill",
		Category:  event.Process,
		PID:       4242,
		Timestamp: time.Now(),
		PS:        testPS("killer", "/usr/bin/killer", 4242, 200),
		Params: event.Params{
			params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint64(4242)},
			params.Signal:          {Name: params.Signal, Type: params.Int32, Value: int32(9)},
			params.TargetProcessID: {Name: params.TargetProcessID, Type: params.PID, Value: uint64(99)},
		},
		Metadata: make(map[event.MetadataKey]any),
	}
	require.True(t, processEvent(t, e, sigkill))

	selfKill := &event.Event{
		Type:      event.Kill,
		Name:      "kill",
		Category:  event.Process,
		PID:       4242,
		Timestamp: time.Now(),
		PS:        testPS("killer", "/usr/bin/killer", 4242, 200),
		Params: event.Params{
			params.ProcessID:       {Name: params.ProcessID, Type: params.PID, Value: uint64(4242)},
			params.Signal:          {Name: params.Signal, Type: params.Int32, Value: int32(9)},
			params.TargetProcessID: {Name: params.TargetProcessID, Type: params.PID, Value: uint64(4242)},
		},
		Metadata: make(map[event.MetadataKey]any),
	}
	require.False(t, processEvent(t, e, selfKill))
}

func TestLinuxLifecycleSequence(t *testing.T) {
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.None}}))

	e := NewEngine(ps.NewSnapshotter(), newLinuxConfig(filepath.Join("..", "..", "rules", "linux", "command_and_control_interpreter_outbound_connection.yml")))
	compileRules(t, e)

	ps := testPS("bash", "/bin/bash", 4242, 200)
	execve := &event.Event{
		Seq:       1,
		Type:      event.Execve,
		Name:      "execve",
		Category:  event.Process,
		PID:       4242,
		Timestamp: time.Now(),
		PS:        ps,
		Params: event.Params{
			params.ProcessID: {Name: params.ProcessID, Type: params.PID, Value: uint64(4242)},
			params.Exe:       {Name: params.Exe, Type: params.Path, Value: "/bin/bash"},
			params.Retval:    {Name: params.Retval, Type: params.Int64, Value: int64(0)},
		},
		Metadata: make(map[event.MetadataKey]any),
	}
	connect := &event.Event{
		Seq:       2,
		Type:      event.Connect,
		Name:      "connect",
		Category:  event.Net,
		PID:       4242,
		Timestamp: time.Now().Add(time.Second),
		PS:        ps,
		Params: event.Params{
			params.ProcessID:  {Name: params.ProcessID, Type: params.PID, Value: uint64(4242)},
			params.SockFamily: {Name: params.SockFamily, Type: params.Uint16, Value: uint16(2)},
			params.NetDIP:     {Name: params.NetDIP, Type: params.IPv4, Value: net.IPv4(1, 2, 3, 4).To4()},
			params.NetDport:   {Name: params.NetDport, Type: params.Port, Value: uint16(4444)},
		},
		Metadata: make(map[event.MetadataKey]any),
	}

	require.False(t, processEvent(t, e, execve))
	require.True(t, processEvent(t, e, connect))
}

func TestSharedSemanticRuleFixtures(t *testing.T) {
	require.NoError(t, alertsender.LoadAll([]alertsender.Config{{Type: alertsender.None}}))

	e := NewEngine(ps.NewSnapshotter(), newLinuxConfig("_fixtures/shared/*.yml"))
	compileRules(t, e)

	proc := &event.Event{
		Type:     event.Execve,
		Name:     "execve",
		Category: event.Process,
		PID:      7,
		PS:       testPS("bash", "/bin/bash", 7, 10),
		Params:   event.Params{},
		Metadata: make(map[event.MetadataKey]any),
	}
	netevt := &event.Event{
		Type:     event.Connect,
		Name:     "connect",
		Category: event.Net,
		PID:      7,
		PS:       testPS("bash", "/bin/bash", 7, 10),
		Params: event.Params{
			params.NetDport: {Name: params.NetDport, Type: params.Port, Value: uint16(443)},
		},
		Metadata: make(map[event.MetadataKey]any),
	}

	require.True(t, processEvent(t, e, proc))
	require.True(t, processEvent(t, e, netevt))
}

func TestCompileKillActionRule(t *testing.T) {
	e := NewEngine(ps.NewSnapshotter(), newLinuxConfig("_fixtures/kill_action_linux.yml"))
	compileRules(t, e)
	assert.NotEmpty(t, e.filters.types[event.Execve])
}
