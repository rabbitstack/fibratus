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

package etw

import (
	"errors"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/rabbitstack/fibratus/pkg/rules"
	"github.com/rabbitstack/fibratus/pkg/util/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type terminated struct {
	pid     uint32
	started time.Time
}

// newTestKiller builds the killer whose terminate function records the calls.
func newTestKiller(opts ...ProcessKillerOption) (*ProcessKiller, *[]terminated, *time.Time) {
	var calls []terminated
	now := testutil.BaseTime()
	k := NewProcessKiller(opts...)
	k.self = 9999
	k.now = func() time.Time { return now }
	k.terminate = func(pid uint32, started time.Time) error {
		calls = append(calls, terminated{pid, started})
		return nil
	}
	return k, &calls, &now
}

func testMatch(t *testing.T, evts ...*event.Event) rules.RuleMatch {
	t.Helper()
	rule, err := rules.NewRule(&policy.RuleDef{ID: "r", Name: "r", Condition: "evt.name = 'CreateFile'"}, nil)
	require.NoError(t, err)
	return rules.RuleMatch{Rule: rule, Events: evts}
}

func psEvent(typ event.Type, pid uint32, name string) *event.Event {
	return testutil.MakeEvent(typ, testutil.WithPID(pid), testutil.WithPS(testutil.MakePS(pid, name)))
}

func TestKillTargets(t *testing.T) {
	create := testutil.MakeEvent(event.CreateProcess,
		testutil.WithPID(100),
		testutil.WithParam(params.ProcessID, params.PID, uint32(200)),
		testutil.WithParam(params.ProcessName, params.UnicodeString, "child.exe"),
	)
	file := psEvent(event.CreateFile, 300, "x.exe")
	again := psEvent(event.WriteFile, 300, "x.exe")
	noPS := testutil.MakeEvent(event.CreateFile, testutil.WithPID(400))

	targets := killTargets([]*event.Event{create, file, again, noPS})
	require.Len(t, targets, 3)

	// the created process rather than the parent
	assert.Equal(t, uint32(200), targets[0].pid)
	assert.Equal(t, "child.exe", targets[0].name)
	assert.Equal(t, create.Timestamp, targets[0].started)
	// unique pids
	assert.Equal(t, uint32(300), targets[1].pid)
	assert.Equal(t, "x.exe", targets[1].name)
	assert.Equal(t, file.PS.StartTime, targets[1].started)
	// events without the process state
	assert.Equal(t, uint32(400), targets[2].pid)
	assert.True(t, targets[2].started.IsZero())
}

func TestKillTargetsCreateProcessWithoutPid(t *testing.T) {
	assert.Empty(t, killTargets([]*event.Event{testutil.MakeEvent(event.CreateProcess)}))
}

func TestProcessKillerKillsProcessesOfMatchedEvents(t *testing.T) {
	k, calls, _ := newTestKiller()
	a := psEvent(event.CreateFile, 100, "a.exe")
	b := psEvent(event.CreateFile, 200, "b.exe")
	require.NoError(t, k.Kill(testMatch(t, a, b)))
	require.Len(t, *calls, 2)
	assert.Equal(t, uint32(100), (*calls)[0].pid)
	assert.Equal(t, a.PS.StartTime, (*calls)[0].started)
	assert.Equal(t, uint32(200), (*calls)[1].pid)
}

func TestProcessKillerNeverKillsProtectedProcesses(t *testing.T) {
	k, calls, _ := newTestKiller()
	evts := []*event.Event{
		psEvent(event.CreateFile, 0, "idle"),
		psEvent(event.CreateFile, 4, "System"),
		psEvent(event.CreateFile, 9999, "fibratus.exe"), // self
		psEvent(event.CreateFile, 500, "lsass.exe"),
		psEvent(event.CreateFile, 501, "CSRSS.EXE"),
		psEvent(event.CreateFile, 502, "wininit.exe"),
		psEvent(event.CreateFile, 503, "services.exe"),
		psEvent(event.CreateFile, 504, "smss.exe"),
		psEvent(event.CreateFile, 505, "winlogon.exe"),
	}
	require.NoError(t, k.Kill(testMatch(t, evts...)))
	assert.Empty(t, *calls)

	// but a regular process is killed
	require.NoError(t, k.Kill(testMatch(t, psEvent(event.CreateFile, 600, "evil.exe"))))
	assert.Len(t, *calls, 1)
}

func TestProcessKillerKillsProcessOnce(t *testing.T) {
	k, calls, now := newTestKiller()
	e := psEvent(event.CreateFile, 100, "a.exe")

	require.NoError(t, k.Kill(testMatch(t, e)))
	require.NoError(t, k.Kill(testMatch(t, e)))
	assert.Len(t, *calls, 1)

	// the process with the same pid, but a different start time is another process
	reused := psEvent(event.CreateFile, 100, "a.exe")
	reused.PS.StartTime = reused.PS.StartTime.Add(time.Hour)
	require.NoError(t, k.Kill(testMatch(t, reused)))
	assert.Len(t, *calls, 2)

	// the record of the kill is forgotten after the ttl
	*now = now.Add(defaultKillTTL + time.Second)
	require.NoError(t, k.Kill(testMatch(t, e)))
	assert.Len(t, *calls, 3)
}

func TestProcessKillerRateLimit(t *testing.T) {
	k, calls, now := newTestKiller(WithKillLimit(2, time.Minute))

	require.NoError(t, k.Kill(testMatch(t, psEvent(event.CreateFile, 100, "a.exe"))))
	require.NoError(t, k.Kill(testMatch(t, psEvent(event.CreateFile, 101, "a.exe"))))
	err := k.Kill(testMatch(t, psEvent(event.CreateFile, 102, "a.exe")))
	require.Error(t, err)
	assert.Contains(t, err.Error(), errKillRateLimited.Error())
	assert.Len(t, *calls, 2)

	// the limit applies to the sliding window
	*now = now.Add(2 * time.Minute)
	require.NoError(t, k.Kill(testMatch(t, psEvent(event.CreateFile, 102, "a.exe"))))
	assert.Len(t, *calls, 3)
}

func TestProcessKillerErrors(t *testing.T) {
	k, calls, _ := newTestKiller()
	k.terminate = func(pid uint32, started time.Time) error {
		*calls = append(*calls, terminated{pid, started})
		switch pid {
		case 100:
			return errors.New("access denied")
		case 200:
			return errPIDReused
		}
		return nil
	}

	err := k.Kill(testMatch(t,
		psEvent(event.CreateFile, 100, "a.exe"),
		psEvent(event.CreateFile, 200, "b.exe"),
		psEvent(event.CreateFile, 300, "c.exe"),
	))
	// the failure doesn't stop the other processes from being killed
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
	assert.Len(t, *calls, 3)

	// the failed kill is retried, the reused pid is not an error
	// and the killed one is not killed twice
	*calls = nil
	err = k.Kill(testMatch(t,
		psEvent(event.CreateFile, 100, "a.exe"),
		psEvent(event.CreateFile, 200, "b.exe"),
		psEvent(event.CreateFile, 300, "c.exe"),
	))
	require.Error(t, err)
	assert.Len(t, *calls, 2)
}
