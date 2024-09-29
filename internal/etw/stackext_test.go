/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestStackExtensions(t *testing.T) {
	cfg := &config.Config{
		Kstream: config.KstreamConfig{
			EnableThreadKevents: true,
			EnableNetKevents:    true,
			EnableFileIOKevents: true,
			BufferSize:          1024,
			FlushTimer:          time.Millisecond * 2300,
		},
	}
	exts := NewStackExtensions(cfg.Kstream)
	assert.Len(t, exts.EventIds(), 0)

	exts.EnableProcessStackTracing()
	exts.EnableRegistryStackTracing()
	exts.EnableFileStackTracing()

	assert.Len(t, exts.EventIds(), 6)
	assert.Contains(t, exts.EventIds(), etw.ClassicEventID{GUID: ktypes.ProcessEventGUID, Type: uint8(ktypes.CreateProcess.HookID())})
	assert.Contains(t, exts.EventIds(), etw.ClassicEventID{GUID: ktypes.ThreadEventGUID, Type: uint8(ktypes.CreateThread.HookID())})
	assert.Contains(t, exts.EventIds(), etw.ClassicEventID{GUID: ktypes.ThreadEventGUID, Type: uint8(ktypes.TerminateThread.HookID())})
	assert.Contains(t, exts.EventIds(), etw.ClassicEventID{GUID: ktypes.FileEventGUID, Type: uint8(ktypes.CreateFile.HookID())})
	assert.Contains(t, exts.EventIds(), etw.ClassicEventID{GUID: ktypes.FileEventGUID, Type: uint8(ktypes.RenameFile.HookID())})
	assert.Contains(t, exts.EventIds(), etw.ClassicEventID{GUID: ktypes.FileEventGUID, Type: uint8(ktypes.DeleteFile.HookID())})
}
