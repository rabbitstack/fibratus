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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeRawEvent(t *testing.T) {
	raw := sampleExecve()
	buf := encodeRaw(t, raw)
	got, err := decodeRawEvent(buf)
	require.NoError(t, err)
	assert.Equal(t, raw.Type, got.Type)
	assert.Equal(t, raw.PID, got.PID)
	assert.Equal(t, raw.StartBootTime, got.StartBootTime)
	assert.Equal(t, "bash", got.comm())
	assert.Equal(t, "/bin/bash", got.filename())
}

func TestRawEventToEventGolden(t *testing.T) {
	evt := sampleExecve().toEvent()
	evt.Seq = 7
	got := goldenEvent(evt)
	path := filepath.Join("testdata", "execve.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, prettyJSON(t, got), 0o644))
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.JSONEq(t, string(want), string(prettyJSON(t, got)))
}

func TestCloneThreadSemantics(t *testing.T) {
	raw := sampleClone(0x00010000)
	evt := raw.toEvent()
	assert.True(t, evt.IsCreateThread())
	assert.False(t, evt.IsCreateProcess())

	raw = sampleClone(0)
	evt = raw.toEvent()
	assert.True(t, evt.IsCreateProcess())
	assert.False(t, evt.IsCreateThread())
}

func sampleExecve() rawEvent {
	var ev rawEvent
	ev.Type = uint32(event.Execve)
	ev.PID = 4242
	ev.TID = 4242
	ev.TGID = 4242
	ev.PPID = 1
	ev.UID = 1000
	ev.GID = 1000
	ev.SyscallID = 59
	ev.Retval = 0
	ev.StartBootTime = 123456789
	ev.TimestampNs = 111
	copy(ev.Comm[:], "bash")
	copy(ev.Filename[:], "/bin/bash")
	return ev
}

func sampleClone(flags uint64) rawEvent {
	var ev rawEvent
	ev.Type = uint32(event.Clone)
	ev.PID = 99
	ev.TID = 100
	ev.TGID = 99
	ev.PPID = 1
	ev.Retval = 99
	ev.Flags = flags
	ev.StartBootTime = 55
	copy(ev.Comm[:], "worker")
	return ev
}

func encodeRaw(t *testing.T, ev rawEvent) []byte {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, ev))
	return buf.Bytes()
}

type golden struct {
	Name   string            `json:"name"`
	PID    uint32            `json:"pid"`
	Tid    uint32            `json:"tid"`
	Seq    uint64            `json:"seq"`
	Params map[string]string `json:"params"`
}

func goldenEvent(evt *event.Event) golden {
	g := golden{
		PID:    evt.PID,
		Tid:    evt.Tid,
		Seq:    evt.Seq,
		Params: map[string]string{},
	}
	for name := range evt.Params {
		g.Params[name] = evt.GetParamAsString(name)
	}
	return g
}

func prettyJSON(t *testing.T, v any) []byte {
	t.Helper()
	buf, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	return append(buf, '\n')
}

func TestSucceededHelper(t *testing.T) {
	evt := sampleExecve().toEvent()
	assert.True(t, succeeded(evt))
	evt.Params.Append(params.Retval, params.Int64, int64(-2))
	assert.False(t, succeeded(evt))
}

// The first argument of kill is a pid_t whose sign selects the scope of the
// signal, so it must survive the conversion to an event parameter.
func TestSignalTargetKeepsPidSign(t *testing.T) {
	var tests = []struct {
		name string
		arg0 uint64
		want int64
	}{
		{"single process", 4242, 4242},
		{"caller process group", 0, 0},
		{"every permitted process", uint64(^uint32(0)), -1},
		{"process group", uint64(uint32(0xFFFFEF6E)), -4242},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			evt := rawEvent{Type: uint32(event.Kill), Arg0: tt.arg0, Arg1: 9}.toEvent()
			target, err := evt.Params.GetInt64(params.TargetProcessID)
			require.NoError(t, err)
			assert.Equal(t, tt.want, target)
		})
	}
}

func TestPtraceAndProcessVMTargetsAreSigned(t *testing.T) {
	ptrace := rawEvent{Type: uint32(event.Ptrace), Arg0: 16, Arg1: 4242}.toEvent()
	target, err := ptrace.Params.GetInt64(params.TargetProcessID)
	require.NoError(t, err)
	assert.Equal(t, int64(4242), target)

	vmread := rawEvent{Type: uint32(event.ProcessVMRead), Arg0: 4242}.toEvent()
	target, err = vmread.Params.GetInt64(params.TargetProcessID)
	require.NoError(t, err)
	assert.Equal(t, int64(4242), target)
}
