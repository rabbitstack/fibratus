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
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestEnabledTypes(t *testing.T) {
	all := enabledTypes(nil)
	assert.True(t, all[event.Execve])
	assert.True(t, all[event.Openat])
	assert.True(t, all[event.Connect])
	assert.True(t, all[event.Mmap])

	off := enabledTypes(&config.EventSourceConfig{})
	assert.True(t, off[event.Execve])
	assert.True(t, off[event.Kill])
	assert.False(t, off[event.Openat])
	assert.False(t, off[event.Connect])
	assert.False(t, off[event.Mmap])

	on := enabledTypes(&config.EventSourceConfig{EnableFileIOEvents: true, EnableNetEvents: true, EnableMemEvents: true})
	assert.True(t, on[event.Openat])
	assert.True(t, on[event.Accept])
	assert.True(t, on[event.ProcessVMRead])
}

func TestIsAttachUnavailable(t *testing.T) {
	assert.False(t, isAttachUnavailable(nil))
	assert.False(t, isAttachUnavailable(errors.New("verifier rejected")))
	assert.True(t, isAttachUnavailable(unix.EPERM))
	assert.True(t, isAttachUnavailable(unix.ENOENT))
	assert.True(t, isAttachUnavailable(os.ErrPermission))
	assert.True(t, isAttachUnavailable(fmt.Errorf("attaching syscalls/sys_enter_fork: cannot create bpf perf link: %w", unix.EPERM)))
	assert.True(t, isAttachUnavailable(errors.New("cannot create bpf perf link: permission denied")))
}
