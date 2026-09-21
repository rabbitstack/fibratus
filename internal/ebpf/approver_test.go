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

package ebpf

import (
	"testing"

	"github.com/rabbitstack/fibratus/internal/ebpf/bpf"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetFilterStoresBeforeOpen(t *testing.T) {
	cfg := testConfig()
	es := NewEventSource(ps.NewSnapshotter(), cfg, nil, nil).(*EventSource)
	f := filter.New("evt.name = 'openat' and file.path startswith '/tmp'", cfg)
	require.NoError(t, f.Compile())
	es.SetFilter(f)
	require.NotNil(t, es.cliPlan)
	pol := es.cliPlan.Policy(event.Openat)
	require.False(t, pol.DefaultAllow)
	assert.True(t, pol.RequireFilename)
	assert.Nil(t, es.loader)
}

func TestReloadApproversWithoutMapsIsNoop(t *testing.T) {
	es := NewEventSource(ps.NewSnapshotter(), testConfig(), nil, nil).(*EventSource)
	require.NoError(t, es.reloadApprovers())
}

func TestPolicyModeKeepsProcessState(t *testing.T) {
	pol := filter.TypePolicy{RequireFilename: true, FilePrefix: []string{"/tmp"}}
	assert.Equal(t, uint8(0), policyMode(pol, event.Execve))
	assert.Equal(t, uint8(0), policyMode(pol, event.Exit))
	assert.Equal(t, uint8(0), policyMode(pol, event.Clone))
	assert.Equal(t, uint8(approverReqFile), policyMode(pol, event.Openat))
}

func TestModeArrayMatchesGeneratedMap(t *testing.T) {
	spec, err := bpf.LoadExecve()
	require.NoError(t, err)
	require.Equal(t, uint32(approverTypeMax*2), spec.Maps[approverModeMapName].MaxEntries,
		"approverTypeMax must mirror EVT_TYPE_MAX in c/common/approvers.h")
}

func BenchmarkApproverReduction(b *testing.B) {
	cfg := &config.Config{
		EventSource: config.EventSourceConfig{EnableFileIOEvents: true},
		Filters:     &config.Filters{},
	}
	f := filter.New("evt.name = 'openat' and file.path startswith '/tmp'", cfg)
	if err := f.Compile(); err != nil {
		b.Fatal(err)
	}
	plan := filter.PlanFromFilter(f)
	paths := []string{"/tmp/a", "/tmp/b", "/var/log/syslog", "/etc/passwd", "/usr/bin/ls"}
	kept := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s := filter.Sample{Type: event.Openat, Filename: paths[i%len(paths)]}
		if plan.Allows(s) {
			kept++
		}
	}
	b.StopTimer()
	if b.N > 0 {
		b.ReportMetric(float64(b.N-kept)/float64(b.N), "drop_ratio")
	}
}

func TestApproverSoundnessTable(t *testing.T) {
	cfg := testConfig()
	cases := []struct {
		expr string
		keep filter.Sample
		drop filter.Sample
	}{
		{
			expr: "evt.name = 'openat' and file.path startswith '/tmp'",
			keep: filter.Sample{Type: event.Openat, Filename: "/tmp/x"},
			drop: filter.Sample{Type: event.Openat, Filename: "/etc/passwd"},
		},
		{
			expr: "evt.name = 'connect' and net.dport in (80, 443)",
			keep: filter.Sample{Type: event.Connect, Port: 443},
			drop: filter.Sample{Type: event.Connect, Port: 22},
		},
		{
			expr: "evt.name = 'kill' and ps.pid = 9",
			keep: filter.Sample{Type: event.Kill, PID: 9},
			drop: filter.Sample{Type: event.Kill, PID: 1},
		},
	}
	for _, tt := range cases {
		t.Run(tt.expr, func(t *testing.T) {
			f := filter.New(tt.expr, cfg)
			require.NoError(t, f.Compile())
			plan := filter.PlanFromFilter(f)
			assert.True(t, plan.Allows(tt.keep), tt.expr)
			assert.False(t, plan.Allows(tt.drop), tt.expr)
		})
	}
}
