/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package kstream

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/syscall/etw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"syscall"
	"testing"
	"time"
)

func TestStartKtrace(t *testing.T) {
	startTrace = func(name string, flags *etw.EventTraceProperties) (etw.TraceHandle, error) {
		return etw.TraceHandle(1), nil
	}
	enableTrace = func(guid syscall.GUID, handle etw.TraceHandle, keyword uint32) error {
		return nil
	}

	ktracec := NewKtraceController(config.KstreamConfig{
		EnableThreadKevents:           true,
		EnableNetKevents:              true,
		BufferSize:                    1024,
		FlushTimer:                    time.Millisecond * 2300,
		EnableAntimalwareEngineEvents: true,
		EnableAuditAPIEvents:          true,
	})

	err := ktracec.StartKtrace()

	require.NoError(t, err)
	assert.Len(t, ktracec.(*ktraceController).traces, 4)
}

func TestStartKtraceNoSysResources(t *testing.T) {
	startTrace = func(name string, props *etw.EventTraceProperties) (etw.TraceHandle, error) {
		return etw.TraceHandle(0), errors.ErrTraceNoSysResources
	}

	ktracec := NewKtraceController(config.KstreamConfig{EnableThreadKevents: true, BufferSize: 1024})

	err := ktracec.StartKtrace()

	require.Error(t, err)
}
