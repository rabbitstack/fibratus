//go:build windows

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
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/eval"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/rabbitstack/fibratus/pkg/util/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seqRule(t *testing.T, condition string) *Rule {
	t.Helper()
	rule, err := NewRule(&policy.RuleDef{ID: "seq", Name: "seq", Condition: condition}, nil)
	require.NoError(t, err)
	require.IsType(t, &ast.SequenceExpr{}, rule.evaluator.GetExpr())
	return rule
}

func evalSeq(rule *Rule, evt *event.Event) ([]*event.Event, bool) {
	valuer := eval.AcquireValuerCache()
	defer valuer.Release()
	return rule.Evaluate(evt, valuer)
}

func pendingSeq(rule *Rule) int {
	return rule.ruleEvaluator.(*SequenceEvaluator).Len()
}

func makeEvent(typ event.Type, pid uint32, opts ...testutil.EventOption) *event.Event {
	opts = append([]testutil.EventOption{
		testutil.WithPID(pid),
		testutil.WithPS(testutil.MakePS(pid, "p.exe", testutil.PSSID("S-1-5-18"))),
	}, opts...)
	return testutil.MakeEvent(typ, opts...)
}

func TestSequenceUnconstrained(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1s
		  |evt.name = 'CreateProcess'|
		  |evt.name = 'CreateFile'|
	`)

	e1 := makeEvent(event.CreateProcess, 1)
	e2 := makeEvent(event.CreateFile, 1, testutil.WithOffset(10*time.Millisecond))

	_, ok := evalSeq(rule, e1)
	assert.False(t, ok)
	assert.Equal(t, 1, pendingSeq(rule))

	evts, ok := evalSeq(rule, e2)
	require.True(t, ok)
	assert.Equal(t, []*event.Event{e1, e2}, evts)
	assert.Equal(t, 0, pendingSeq(rule))

	// the sequence doesn't match again without the first step
	_, ok = evalSeq(rule, makeEvent(event.CreateFile, 1))
	assert.False(t, ok)
}

func TestSequenceWrongOrder(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1s
		  |evt.name = 'CreateProcess'|
		  |evt.name = 'CreateFile'|
	`)
	_, ok := evalSeq(rule, makeEvent(event.CreateFile, 1))
	assert.False(t, ok)
	_, ok = evalSeq(rule, makeEvent(event.CreateProcess, 1, testutil.WithOffset(time.Millisecond)))
	assert.False(t, ok)
	assert.Equal(t, 1, pendingSeq(rule))
}

func TestSequenceThreeSteps(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1s
		  |evt.name = 'CreateProcess'|
		  |evt.name = 'CreateFile'|
		  |evt.name = 'Connect'|
	`)
	e1 := makeEvent(event.CreateProcess, 1)
	e2 := makeEvent(event.CreateFile, 1, testutil.WithOffset(time.Millisecond))
	e3 := makeEvent(event.Connect, 1, testutil.WithOffset(2*time.Millisecond))

	_, ok := evalSeq(rule, e1)
	assert.False(t, ok)
	_, ok = evalSeq(rule, e2)
	assert.False(t, ok)
	// a chain in the middle of the ladder is not a match
	assert.Equal(t, 1, pendingSeq(rule))
	evts, ok := evalSeq(rule, e3)
	require.True(t, ok)
	assert.Equal(t, []*event.Event{e1, e2, e3}, evts)
}

func TestSequenceEventAdvancesSingleStage(t *testing.T) {
	// both steps match the same events, but one event can't seed
	// the chain and complete it at the same time
	rule := seqRule(t, `
		sequence
		  maxspan 1s
		  |evt.name = 'CreateFile'|
		  |evt.name = 'CreateFile'|
	`)
	e1 := makeEvent(event.CreateFile, 1)
	e2 := makeEvent(event.CreateFile, 1, testutil.WithOffset(time.Millisecond))

	_, ok := evalSeq(rule, e1)
	require.False(t, ok)
	evts, ok := evalSeq(rule, e2)
	require.True(t, ok)
	assert.Equal(t, []*event.Event{e1, e2}, evts)
}

func TestSequenceSingleStageMiddleStepDoesNotSkip(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1s
		  |evt.name = 'CreateFile'|
		  |evt.name = 'CreateFile'|
		  |evt.name = 'CreateFile'|
	`)
	var matched int
	for i := range 2 {
		_, ok := evalSeq(rule, makeEvent(event.CreateFile, 1, testutil.WithOffset(time.Duration(i)*time.Millisecond)))
		if ok {
			matched++
		}
	}
	// two events can't satisfy three steps
	assert.Equal(t, 0, matched)
	_, ok := evalSeq(rule, makeEvent(event.CreateFile, 1, testutil.WithOffset(5*time.Millisecond)))
	assert.True(t, ok)
}

func TestSequenceJoinedByLink(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1m
		  |evt.name = 'CreateProcess'| by ps.pid
		  |evt.name = 'CreateFile'| by ps.pid
	`)

	_, ok := evalSeq(rule, makeEvent(event.CreateProcess, 1))
	require.False(t, ok)
	_, ok = evalSeq(rule, makeEvent(event.CreateProcess, 2, testutil.WithOffset(time.Millisecond)))
	require.False(t, ok)
	assert.Equal(t, 2, pendingSeq(rule))

	// no chain was started by the process
	_, ok = evalSeq(rule, makeEvent(event.CreateFile, 3, testutil.WithOffset(2*time.Millisecond)))
	assert.False(t, ok)

	evts, ok := evalSeq(rule, makeEvent(event.CreateFile, 2, testutil.WithOffset(3*time.Millisecond)))
	require.True(t, ok)
	require.Len(t, evts, 2)
	assert.Equal(t, uint32(2), evts[0].PID)
	assert.Equal(t, 1, pendingSeq(rule))

	evts, ok = evalSeq(rule, makeEvent(event.CreateFile, 1, testutil.WithOffset(4*time.Millisecond)))
	require.True(t, ok)
	assert.Equal(t, uint32(1), evts[0].PID)
	assert.Equal(t, 0, pendingSeq(rule))
}

func TestSequenceGlobalLink(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1m
		  by ps.pid
		  |evt.name = 'CreateProcess'|
		  |evt.name = 'CreateFile'|
		  |evt.name = 'Connect'|
	`)
	_, ok := evalSeq(rule, makeEvent(event.CreateProcess, 1))
	require.False(t, ok)
	_, ok = evalSeq(rule, makeEvent(event.CreateFile, 1))
	require.False(t, ok)
	_, ok = evalSeq(rule, makeEvent(event.Connect, 2))
	assert.False(t, ok)
	evts, ok := evalSeq(rule, makeEvent(event.Connect, 1))
	require.True(t, ok)
	assert.Len(t, evts, 3)
}

func TestSequenceNewerSeedSupersedesPendingChain(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1m
		  |evt.name = 'CreateProcess'| by ps.pid
		  |evt.name = 'CreateFile'| by ps.pid
	`)
	old := makeEvent(event.CreateProcess, 1)
	recent := makeEvent(event.CreateProcess, 1, testutil.WithOffset(time.Millisecond))
	_, _ = evalSeq(rule, old)
	_, _ = evalSeq(rule, recent)
	assert.Equal(t, 1, pendingSeq(rule))

	evts, ok := evalSeq(rule, makeEvent(event.CreateFile, 1, testutil.WithOffset(2*time.Millisecond)))
	require.True(t, ok)
	assert.Same(t, recent, evts[0])
}

func TestSequenceBoundFields(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1m
		  |evt.name = 'CreateProcess'| as e1
		  |evt.name = 'CreateFile' and ps.sid = $e1.ps.sid|
	`)

	proc := testutil.MakeEvent(event.CreateProcess, testutil.WithPS(testutil.MakePS(1, "a.exe", testutil.PSSID("S-1-5-21"))))
	_, ok := evalSeq(rule, proc)
	require.False(t, ok)

	// the bound condition doesn't hold
	_, ok = evalSeq(rule, testutil.MakeEvent(event.CreateFile,
		testutil.WithOffset(time.Millisecond),
		testutil.WithPS(testutil.MakePS(2, "b.exe", testutil.PSSID("S-1-5-99")))))
	assert.False(t, ok)
	assert.Equal(t, 1, pendingSeq(rule))

	file := testutil.MakeEvent(event.CreateFile,
		testutil.WithOffset(2*time.Millisecond),
		testutil.WithPS(testutil.MakePS(3, "c.exe", testutil.PSSID("S-1-5-21"))))
	evts, ok := evalSeq(rule, file)
	require.True(t, ok)
	assert.Equal(t, []*event.Event{proc, file}, evts)
	assert.Equal(t, 0, pendingSeq(rule))
}

func TestSequenceBoundFieldsKeepMultiplePendingChains(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1m
		  |evt.name = 'CreateProcess'| as e1
		  |evt.name = 'CreateFile' and ps.sid = $e1.ps.sid|
	`)
	mk := func(typ event.Type, pid uint32, sid string, off time.Duration) *event.Event {
		return testutil.MakeEvent(typ, testutil.WithOffset(off),
			testutil.WithPS(testutil.MakePS(pid, "x.exe", testutil.PSSID(sid))))
	}
	a := mk(event.CreateProcess, 1, "A", 0)
	b := mk(event.CreateProcess, 2, "B", time.Millisecond)
	_, _ = evalSeq(rule, a)
	_, _ = evalSeq(rule, b)
	// no key joins the chains, so both stay pending
	assert.Equal(t, 2, pendingSeq(rule))

	evts, ok := evalSeq(rule, mk(event.CreateFile, 9, "B", 2*time.Millisecond))
	require.True(t, ok)
	assert.Same(t, b, evts[0])
	assert.Equal(t, 1, pendingSeq(rule))

	evts, ok = evalSeq(rule, mk(event.CreateFile, 9, "A", 3*time.Millisecond))
	require.True(t, ok)
	assert.Same(t, a, evts[0])
	assert.Equal(t, 0, pendingSeq(rule))
}

func TestSequenceBoundFieldsPickOldestChain(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1m
		  |evt.name = 'CreateProcess'| as e1
		  |evt.name = 'CreateFile' and ps.sid = $e1.ps.sid|
	`)
	mk := func(typ event.Type, pid uint32, off time.Duration) *event.Event {
		return testutil.MakeEvent(typ, testutil.WithOffset(off),
			testutil.WithPS(testutil.MakePS(pid, "x.exe", testutil.PSSID("S"))))
	}
	first := mk(event.CreateProcess, 1, 0)
	second := mk(event.CreateProcess, 2, time.Millisecond)
	_, _ = evalSeq(rule, first)
	_, _ = evalSeq(rule, second)

	evts, ok := evalSeq(rule, mk(event.CreateFile, 3, 2*time.Millisecond))
	require.True(t, ok)
	assert.Same(t, first, evts[0])
	assert.Equal(t, 1, pendingSeq(rule))
}

func TestSequenceBoundFieldsAcrossSeveralAliases(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1m
		  |evt.name = 'CreateProcess'| as e1
		  |evt.name = 'CreateFile' and ps.sid = $e1.ps.sid| as e2
		  |evt.name = 'Connect' and ps.sid = $e1.ps.sid and ps.pid != $e2.ps.pid|
	`)
	mk := func(typ event.Type, pid uint32, sid string, off time.Duration) *event.Event {
		return testutil.MakeEvent(typ, testutil.WithOffset(off),
			testutil.WithPS(testutil.MakePS(pid, "x.exe", testutil.PSSID(sid))))
	}
	_, _ = evalSeq(rule, mk(event.CreateProcess, 1, "A", 0))
	_, _ = evalSeq(rule, mk(event.CreateFile, 2, "A", time.Millisecond))

	// same pid as the second step
	_, ok := evalSeq(rule, mk(event.Connect, 2, "A", 2*time.Millisecond))
	assert.False(t, ok)
	// the sid differs from the first step
	_, ok = evalSeq(rule, mk(event.Connect, 3, "B", 3*time.Millisecond))
	assert.False(t, ok)

	evts, ok := evalSeq(rule, mk(event.Connect, 3, "A", 4*time.Millisecond))
	require.True(t, ok)
	assert.Len(t, evts, 3)
}

func TestSequenceBoundFieldsWithLink(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1m
		  by ps.pid
		  |evt.name = 'CreateProcess'| as e1
		  |evt.name = 'CreateFile' and ps.name = $e1.ps.name|
	`)
	mk := func(typ event.Type, pid uint32, name string, off time.Duration) *event.Event {
		return testutil.MakeEvent(typ, testutil.WithOffset(off), testutil.WithPS(testutil.MakePS(pid, name)))
	}
	_, _ = evalSeq(rule, mk(event.CreateProcess, 1, "a.exe", 0))
	// the link matches, the bound condition doesn't
	_, ok := evalSeq(rule, mk(event.CreateFile, 1, "b.exe", time.Millisecond))
	assert.False(t, ok)
	// the bound condition matches, the link doesn't
	_, ok = evalSeq(rule, mk(event.CreateFile, 2, "a.exe", 2*time.Millisecond))
	assert.False(t, ok)
	_, ok = evalSeq(rule, mk(event.CreateFile, 1, "a.exe", 3*time.Millisecond))
	assert.True(t, ok)
}

func TestSequenceInvalidBoundReferences(t *testing.T) {
	var tests = []struct {
		name string
		cond string
		err  string
	}{
		{
			"unknown alias",
			`sequence maxspan 1m |evt.name = 'CreateProcess'| as e1 |evt.name = 'CreateFile' and ps.sid = $e2.ps.sid|`,
			"unknown or a later sequence alias $e2",
		},
		{
			"alias of the same step",
			`sequence maxspan 1m |evt.name = 'CreateProcess' and ps.sid = $e1.ps.sid| as e1 |evt.name = 'CreateFile'|`,
			"unknown or a later sequence alias $e1",
		},
		{
			"alias of the later step",
			`sequence maxspan 1m |evt.name = 'CreateProcess' and ps.sid = $e2.ps.sid| as e1 |evt.name = 'CreateFile'| as e2`,
			"unknown or a later sequence alias $e2",
		},
		{
			"duplicate alias",
			`sequence maxspan 1m |evt.name = 'CreateProcess'| as e1 |evt.name = 'CreateFile'| as e1 |evt.name = 'Connect'|`,
			"duplicate alias $e1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRule(&policy.RuleDef{ID: "x", Name: "x", Condition: tt.cond}, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}

func TestSequenceMaxSpanTimerDropsChain(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 30ms
		  |evt.name = 'CreateProcess'| by ps.pid
		  |evt.name = 'CreateFile'| by ps.pid
		  |evt.name = 'Connect'| by ps.pid
	`)
	_, _ = evalSeq(rule, makeEvent(event.CreateProcess, 1))
	_, _ = evalSeq(rule, makeEvent(event.CreateProcess, 2))
	// move one of the chains to the second stage
	_, _ = evalSeq(rule, makeEvent(event.CreateFile, 2))
	require.Equal(t, 2, pendingSeq(rule))

	// the timer removes the chain from whichever stage it occupies
	require.Eventually(t, func() bool { return pendingSeq(rule) == 0 }, 2*time.Second, 5*time.Millisecond)

	_, ok := evalSeq(rule, makeEvent(event.Connect, 2))
	assert.False(t, ok)
}

func TestSequenceCompletedChainCancelsTimer(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 30ms
		  |evt.name = 'CreateProcess'| by ps.pid
		  |evt.name = 'CreateFile'| by ps.pid
	`)
	_, _ = evalSeq(rule, makeEvent(event.CreateProcess, 1))
	_, ok := evalSeq(rule, makeEvent(event.CreateFile, 1))
	require.True(t, ok)

	seq := rule.ruleEvaluator.(*SequenceEvaluator)
	// a new chain with the same key isn't affected by the timer of the completed one
	_, _ = evalSeq(rule, makeEvent(event.CreateProcess, 1))
	time.Sleep(10 * time.Millisecond)
	assert.Equal(t, 1, seq.Len())
}

func TestSequenceEventTimestampBeyondMaxSpan(t *testing.T) {
	// the second event arrives before the timer fires, but its
	// timestamp is past the deadline
	rule := seqRule(t, `
		sequence
		  maxspan 1s
		  |evt.name = 'CreateProcess'| by ps.pid
		  |evt.name = 'CreateFile'| by ps.pid
	`)
	_, _ = evalSeq(rule, makeEvent(event.CreateProcess, 1))
	_, ok := evalSeq(rule, makeEvent(event.CreateFile, 1, testutil.WithOffset(2*time.Second)))
	assert.False(t, ok)
	assert.Equal(t, 0, pendingSeq(rule))

	_, _ = evalSeq(rule, makeEvent(event.CreateProcess, 1))
	_, ok = evalSeq(rule, makeEvent(event.CreateFile, 1, testutil.WithOffset(500*time.Millisecond)))
	assert.True(t, ok)
}

func TestSequenceExpire(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1m
		  |evt.name = 'CreateProcess'| by ps.pid
		  |evt.name = 'CreateFile'| by ps.pid
	`)
	_, _ = evalSeq(rule, makeEvent(event.CreateProcess, 10, testutil.WithParam(params.ProcessID, params.PID, uint32(10))))
	_, _ = evalSeq(rule, makeEvent(event.CreateProcess, 20, testutil.WithParam(params.ProcessID, params.PID, uint32(20))))
	require.Equal(t, 2, pendingSeq(rule))

	terminate := func(pid uint32) *event.Event {
		return testutil.MakeEvent(event.TerminateProcess, testutil.WithParam(params.ProcessID, params.PID, pid))
	}

	evalSeq(rule, terminate(10))

	assert.Equal(t, 1, pendingSeq(rule))
	_, ok := evalSeq(rule, makeEvent(event.CreateFile, 10))
	assert.False(t, ok)
	_, ok = evalSeq(rule, makeEvent(event.CreateFile, 20))
	assert.True(t, ok)
	require.Equal(t, 0, pendingSeq(rule))
}

func TestSequenceExpireTerminateProcessFinalStage(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1m
		  |evt.name = 'CreateProcess'| by ps.pid
		  |evt.name = 'CreateProcess'| by ps.parent.pid
	`)

	_, _ = evalSeq(rule, makeEvent(event.CreateProcess, 10, testutil.WithParam(params.ProcessID, params.PID, uint32(10)), testutil.WithPS(testutil.MakePS(10, "rundll32.exe", testutil.PSPpid(30)))))
	_, _ = evalSeq(rule, makeEvent(event.CreateProcess, 20, testutil.WithParam(params.ProcessID, params.PID, uint32(20)), testutil.WithPS(testutil.MakePS(20, "cmd.exe", testutil.PSPpid(10)))))
	require.Equal(t, 2, pendingSeq(rule))

	terminate := func(pid uint32) *event.Event {
		return testutil.MakeEvent(event.TerminateProcess, testutil.WithParam(params.ProcessID, params.PID, pid))
	}

	evalSeq(rule, terminate(10))

	// the sequence is expired when the terminate process
	// event arrives for the create process in the final stage.
	// Since the termination arrived for event in the first stage
	// the sequence remains intact.
	assert.Equal(t, 2, pendingSeq(rule))

	// termination of the process in the final stage expires the sequence
	evalSeq(rule, terminate(20))
	require.Equal(t, 0, pendingSeq(rule))
}

func TestSequenceExpireRemoteThread(t *testing.T) {
	rule := seqRule(t, `
		sequence
		  maxspan 1m
		  |evt.name = 'CreateThread'|
		  |evt.name = 'CreateFile'|
	`)
	// thread created by the process 10 in the process 20
	_, _ = evalSeq(rule, makeEvent(event.CreateThread, 10, testutil.WithParam(params.ProcessID, params.PID, uint32(20))))

	terminate := func(pid uint32) *event.Event {
		return testutil.MakeEvent(event.TerminateProcess, testutil.WithParam(params.ProcessID, params.PID, pid))
	}

	// the creator terminates, but the target process is alive
	evalSeq(rule, terminate(10))
	assert.Equal(t, 1, pendingSeq(rule))
	evalSeq(rule, terminate(20))
	assert.Equal(t, 0, pendingSeq(rule))
}
