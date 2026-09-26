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

package event

import (
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/util/filetime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func makeEvent(pid, tid uint32, cpu uint8, ts uint64, typ Type, pars ...Param) *Event {
	e := &Event{
		PID:       pid,
		Tid:       tid,
		CPU:       cpu,
		Type:      typ,
		Timestamp: filetime.ToEpoch(ts),
		Params:    Params{},
	}

	for _, par := range pars {
		e.Params.Append(par.Name, par.Type, par.Value)
	}

	return e
}

func makeStackWalk(pid, tid uint32, cpu uint8, triggerTS uint64, addrs []uintptr) *Event {
	e := &Event{
		PID:       pid,
		Tid:       tid,
		CPU:       cpu,
		Type:      StackWalk,
		Timestamp: filetime.ToEpoch(triggerTS + 50), // slight offset to prove we don't use StackWalk timestamp
		Params:    Params{},
	}
	e.Params.Append(params.CallstackTimestamp, params.Uint64, triggerTS)
	e.Params.Append(params.ProcessID, params.PID, pid)
	e.Params.Append(params.ThreadID, params.TID, tid)
	e.Params.Append(params.Callstack, params.Slice, addrs)
	return e
}

func newTestDecorator() (*StackwalkDecorator, *Queue) {
	q := NewQueue(100, true, true)
	d := NewStackwalkDecorator(q)
	return d, q
}

func TestPushThenPop(t *testing.T) {
	d, _ := newTestDecorator()
	defer d.Stop()

	const ts = uint64(133_000_000_000_000_000)
	addrs := []uintptr{0xDEAD, 0xBEEF}

	e := makeEvent(100, 200, 3, ts, LoadModule)
	d.Push(e)

	sw := makeStackWalk(100, 200, 3, ts, addrs)
	got := d.Pop(sw)

	require.NotNil(t, got)
	assert.Equal(t, e, got)
	callstack, err := got.Params.GetSlice(params.Callstack)
	require.NoError(t, err)
	assert.Equal(t, addrs, callstack)
}

func TestPopThenPush(t *testing.T) {
	d, q := newTestDecorator()
	defer d.Stop()

	const ts = uint64(133_000_000_000_000_001)
	addrs := []uintptr{0xCAFE, 0xBABE}

	sw := makeStackWalk(100, 200, 3, ts, addrs)
	got := d.Pop(sw)
	assert.Equal(t, sw, got, "Pop should return the stackwalk itself when trigger not yet seen")

	e := makeEvent(100, 200, 3, ts, LoadModule)
	d.Push(e)

	// event should have been pushed directly to the queue with callstack attached
	queued := <-q.Events()
	require.NotNil(t, queued)
	callstack, err := queued.Params.GetSlice(params.Callstack)
	require.NoError(t, err)
	assert.Equal(t, addrs, callstack)
}

func TestSurrogateProcess(t *testing.T) {
	d, _ := newTestDecorator()
	defer d.Stop()

	const ts = uint64(133_000_000_000_000_010)
	addrs := []uintptr{0xFACE}

	// surrogate CreateProcess event
	pars := []Param{
		{Name: params.ProcessID, Type: params.PID, Value: uint32(500)},
		{Name: params.ProcessParentID, Type: params.PID, Value: uint32(1999)},
		{Name: params.ProcessRealParentID, Type: params.PID, Value: uint32(2929)},
	}
	e := makeEvent(500, 600, 1, ts, CreateProcess, pars...)
	d.Push(e)

	sw := makeStackWalk(500, 600, 1, ts, addrs)
	got := d.Pop(sw)
	require.NotNil(t, got)

	// surrogate entry should be cleaned up after match
	d.mux.Lock()
	_, stillPresent := d.procs[500]
	d.mux.Unlock()
	assert.False(t, stillPresent, "surrogate proc entry should be deleted after pop")
}

func TestCreateRemoteThreadForwardToSurrogate(t *testing.T) {
	d, q := newTestDecorator()
	defer d.Stop()

	const tsProc = uint64(133_000_000_000_000_020)
	const tsThread = uint64(133_000_000_000_000_021)
	addrs := []uintptr{0x1234, 0x5678}

	// park the surrogate CreateProcess event
	pars := []Param{
		{Name: params.ProcessID, Type: params.PID, Value: uint32(1700)},
		{Name: params.ProcessParentID, Type: params.PID, Value: uint32(1999)},
		{Name: params.ProcessRealParentID, Type: params.PID, Value: uint32(2929)},
	}
	procEvt := makeEvent(1700, 800, 0, tsProc, CreateProcess, pars...)
	d.Push(procEvt)

	// park the CreateRemoteThread event targeting the surrogate pid
	threadEvt := makeEvent(700, 801, 0, tsThread, CreateThread, Param{Name: params.ProcessID, Type: params.PID, Value: uint32(1700)})
	d.Push(threadEvt)

	sw := makeStackWalk(700, 801, 0, tsThread, addrs)
	d.Pop(sw)

	// the surrogate proc event should have been pushed to the queue with the callstack
	queued := <-q.Events()
	require.True(t, queued.IsCreateProcess())
	cs, err := queued.Params.GetSlice(params.Callstack)
	require.NoError(t, err)
	assert.Equal(t, addrs, cs)
}

func TestFlushExpiredEvents(t *testing.T) {
	// shrink TTL and flusher interval for the test
	origTTL := maxQueueTTLPeriod
	origInterval := flusherInterval
	maxQueueTTLPeriod = 100 * time.Millisecond
	flusherInterval = 50 * time.Millisecond
	defer func() {
		maxQueueTTLPeriod = origTTL
		flusherInterval = origInterval
	}()

	d, q := newTestDecorator()
	defer d.Stop()

	const ts = uint64(133_000_000_000_000_030)
	e := makeEvent(900, 901, 0, ts, LoadModule)
	d.Push(e)

	// wait for TTL + flusher to run
	time.Sleep(300 * time.Millisecond)

	queued := q.Events()
	require.Len(t, queued, 1, "expired event should be flushed to queue without callstack")
	assert.Equal(t, e, <-queued)
}

func TestFlushDoesNotExpireRecentEvents(t *testing.T) {
	origTTL := maxQueueTTLPeriod
	origInterval := flusherInterval
	maxQueueTTLPeriod = 500 * time.Millisecond
	flusherInterval = 100 * time.Millisecond
	defer func() {
		maxQueueTTLPeriod = origTTL
		flusherInterval = origInterval
	}()

	d, q := newTestDecorator()
	defer d.Stop()

	const ts = uint64(133_000_000_000_000_040)
	e := makeEvent(902, 903, 0, ts, LoadModule)
	d.Push(e)

	// wait less than TTL
	time.Sleep(80 * time.Millisecond)

	assert.Empty(t, q.Events())
}

func TestPopSkipsSelfStackWalk(t *testing.T) {
	d, _ := newTestDecorator()
	defer d.Stop()

	const ts = uint64(133_000_000_000_000_050)
	addrs := []uintptr{0xDEAD}

	sw := makeStackWalk(currentPid, 100, 0, ts, addrs)
	d.Pop(sw)

	d.mux.Lock()
	_, parked := d.buckets[ts]
	d.mux.Unlock()

	assert.False(t, parked, "self-pid stackwalk should not be parked in buckets")
}

func TestNoCallstackCrossContamination(t *testing.T) {
	d, _ := newTestDecorator()
	defer d.Stop()

	const tsA = uint64(133_000_000_000_000_060)
	const tsB = uint64(133_000_000_000_000_061)
	addrsA := []uintptr{0xAAAA}
	addrsB := []uintptr{0xBBBB}

	eA := makeEvent(100, 200, 0, tsA, RegCreateKey)
	eB := makeEvent(100, 200, 0, tsB, RegCreateKey)
	d.Push(eA)
	d.Push(eB)

	swB := makeStackWalk(100, 200, 0, tsB, addrsB)
	swA := makeStackWalk(100, 200, 0, tsA, addrsA)

	gotB := d.Pop(swB)
	gotA := d.Pop(swA)

	csA, _ := gotA.Params.GetSlice(params.Callstack)
	csB, _ := gotB.Params.GetSlice(params.Callstack)

	assert.Equal(t, addrsA, csA, "event A must not receive event B's callstack")
	assert.Equal(t, addrsB, csB, "event B must not receive event A's callstack")
}
