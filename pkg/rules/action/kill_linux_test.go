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

package action

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	testPID        = 4242
	testStartNs    = uint64(1_234_500_000_000)
	testStartTicks = testStartNs / nsecPerTick
	testPidfd      = 7
)

// recorder captures what a killer attempted so tests never signal a real process.
type recorder struct {
	opened   []uint32
	signaled []int
	signals  []unix.Signal
	closed   []int
}

func (r *recorder) killer(ticks func(pid uint32) (uint64, error)) killer {
	return killer{
		open: func(pid uint32) (int, error) {
			r.opened = append(r.opened, pid)
			return testPidfd, nil
		},
		readStartTicks: ticks,
		signal: func(fd int, sig unix.Signal) error {
			r.signaled = append(r.signaled, fd)
			r.signals = append(r.signals, sig)
			return nil
		},
		closeFD: func(fd int) error {
			r.closed = append(r.closed, fd)
			return nil
		},
	}
}

func constTicks(ticks uint64) func(uint32) (uint64, error) {
	return func(uint32) (uint64, error) { return ticks, nil }
}

func killEvent(pid uint32, startNs uint64) *event.Event {
	return &event.Event{
		Type: event.Execve,
		PID:  pid,
		PS: &pstypes.PS{
			PID:           pid,
			Name:          "malware",
			StartBootTime: startNs,
		},
		Params: event.Params{
			params.ProcessID:     {Name: params.ProcessID, Type: params.PID, Value: pid},
			params.StartBootTime: {Name: params.StartBootTime, Type: params.Uint64, Value: startNs},
		},
	}
}

func killContext(evts ...*event.Event) *config.ActionContext {
	return &config.ActionContext{Events: evts}
}

func TestParseProcStatStartTicks(t *testing.T) {
	stat := []byte("1 (systemd) S 0 1 1 0 -1 4194560 123 0 0 0 1 1 0 0 20 0 1 0 12345 123456 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
	ticks, err := parseProcStatStartTicks(stat)
	require.NoError(t, err)
	assert.Equal(t, uint64(12345), ticks)

	// comm may contain spaces and parentheses
	spaced := []byte("4242 (my (odd) process) S 1 4242 4242 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
	ticks, err = parseProcStatStartTicks(spaced)
	require.NoError(t, err)
	assert.Equal(t, uint64(99), ticks)

	_, err = parseProcStatStartTicks([]byte("1 systemd S 0 1"))
	require.Error(t, err)
	_, err = parseProcStatStartTicks([]byte("1 (systemd) S 0"))
	require.Error(t, err)
}

func TestReadProcStartTicks(t *testing.T) {
	ticks, err := readProcStartTicks(uint32(os.Getpid()))
	require.NoError(t, err)
	assert.Greater(t, ticks, uint64(0))

	_, err = readProcStartTicks(uint32(1 << 30))
	require.Error(t, err)
	assert.True(t, isGone(err))
}

func TestKillSignalsMatchingInstance(t *testing.T) {
	r := &recorder{}
	k := r.killer(constTicks(testStartTicks))

	require.NoError(t, k.kill(killContext(killEvent(testPID, testStartNs))))
	assert.Equal(t, []uint32{testPID}, r.opened)
	assert.Equal(t, []int{testPidfd}, r.signaled)
	assert.Equal(t, []unix.Signal{unix.SIGKILL}, r.signals)
	assert.Equal(t, []int{testPidfd}, r.closed)
}

func TestKillPinsProcessBeforeRevalidating(t *testing.T) {
	r := &recorder{}
	var openedBeforeRead bool
	k := r.killer(func(uint32) (uint64, error) {
		openedBeforeRead = len(r.opened) == 1
		return testStartTicks, nil
	})

	require.NoError(t, k.kill(killContext(killEvent(testPID, testStartNs))))
	assert.True(t, openedBeforeRead, "pidfd must be open before the start time is compared")
}

func TestKillRefusesReusedPID(t *testing.T) {
	r := &recorder{}
	k := r.killer(constTicks(testStartTicks + 1))

	err := k.kill(killContext(killEvent(testPID, testStartNs)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "process instance identity does not match")
	assert.Empty(t, r.signaled)
	assert.Equal(t, []int{testPidfd}, r.closed)
}

func TestKillMissingProcessIsSuccess(t *testing.T) {
	r := &recorder{}
	k := r.killer(constTicks(testStartTicks))
	k.open = func(uint32) (int, error) { return 0, unix.ESRCH }

	require.NoError(t, k.kill(killContext(killEvent(testPID, testStartNs))))
	assert.Empty(t, r.signaled)
}

func TestKillProcessExitingDuringRevalidationIsSuccess(t *testing.T) {
	r := &recorder{}
	k := r.killer(func(uint32) (uint64, error) { return 0, os.ErrNotExist })

	require.NoError(t, k.kill(killContext(killEvent(testPID, testStartNs))))
	assert.Empty(t, r.signaled)
	assert.Equal(t, []int{testPidfd}, r.closed)
}

func TestKillESRCHOnSignalIsSuccess(t *testing.T) {
	r := &recorder{}
	k := r.killer(constTicks(testStartTicks))
	k.signal = func(int, unix.Signal) error { return unix.ESRCH }

	require.NoError(t, k.kill(killContext(killEvent(testPID, testStartNs))))
}

func TestKillRefusesMissingStartTime(t *testing.T) {
	r := &recorder{}
	k := r.killer(constTicks(testStartTicks))

	evt := killEvent(testPID, 0)
	evt.PS.StartBootTime = 0
	evt.Params.Remove(params.StartBootTime)

	err := k.kill(killContext(evt))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing process start time")
	assert.Empty(t, r.opened)
	assert.Empty(t, r.signaled)
}

func TestKillUsesEventStartBootTimeWhenPSMissing(t *testing.T) {
	r := &recorder{}
	k := r.killer(constTicks(testStartTicks))

	evt := killEvent(testPID, testStartNs)
	evt.PS = nil
	require.NoError(t, k.kill(killContext(evt)))
	assert.Equal(t, []uint32{testPID}, r.opened)
}

// Clone events carry the child identity, so the event pid designates the
// process the rule matched on without consulting the pid parameter.
func TestKillResolvesCloneChildPid(t *testing.T) {
	r := &recorder{}
	k := r.killer(constTicks(testStartTicks))

	clone := killEvent(testPID, testStartNs)
	clone.Type = event.Clone
	clone.Params.Append(params.CloneFlags, params.Uint64, uint64(0))
	require.True(t, clone.IsCreateProcess())

	require.NoError(t, k.kill(killContext(clone)))
	assert.Equal(t, []uint32{testPID}, r.opened)
}

func TestKillDeduplicatesAndOrdersPids(t *testing.T) {
	r := &recorder{}
	k := r.killer(constTicks(testStartTicks))

	err := k.kill(killContext(
		killEvent(90, testStartNs),
		killEvent(12, testStartNs),
		killEvent(90, testStartNs),
	))
	require.NoError(t, err)
	assert.Equal(t, []uint32{12, 90}, r.opened)
}

func TestKillNilContext(t *testing.T) {
	require.NoError(t, Kill(nil))
}

// TestKillTerminatesLiveProcess exercises the real pidfd and procfs path end to
// end, including the refusal branch when the captured start time disagrees.
func TestKillTerminatesLiveProcess(t *testing.T) {
	start := func(t *testing.T) (uint32, *exec.Cmd, uint64) {
		t.Helper()
		cmd := exec.Command("sleep", "300")
		require.NoError(t, cmd.Start())
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		})
		pid := uint32(cmd.Process.Pid)
		ticks, err := readProcStartTicks(pid)
		require.NoError(t, err)
		return pid, cmd, ticks * nsecPerTick
	}

	t.Run("matching instance is terminated", func(t *testing.T) {
		pid, cmd, startNs := start(t)

		require.NoError(t, Kill(killContext(killEvent(pid, startNs))))

		state, err := cmd.Process.Wait()
		require.NoError(t, err)
		assert.Equal(t, syscall.SIGKILL, state.Sys().(syscall.WaitStatus).Signal())
	})

	t.Run("mismatched instance is spared", func(t *testing.T) {
		pid, _, startNs := start(t)

		err := Kill(killContext(killEvent(pid, startNs+uint64(time.Second))))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "process instance identity does not match")

		ticks, err := readProcStartTicks(pid)
		require.NoError(t, err)
		assert.Equal(t, startNs/nsecPerTick, ticks, "process should still be alive")
	})
}

func TestOpenPidfdRejectsOutOfRangePid(t *testing.T) {
	_, err := openPidfd(uint32(1) << 30)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestKillReportsUnexpectedOpenError(t *testing.T) {
	r := &recorder{}
	k := r.killer(constTicks(testStartTicks))
	k.open = func(uint32) (int, error) { return 0, fmt.Errorf("boom") }

	err := k.kill(killContext(killEvent(testPID, testStartNs)))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "couldn't pin pid 4242")
}
