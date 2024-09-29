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
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestStartTrace(t *testing.T) {
	cfg := &config.Config{
		Kstream: config.KstreamConfig{
			EnableThreadKevents: true,
			EnableNetKevents:    true,
			EnableFileIOKevents: true,
			BufferSize:          1024,
			FlushTimer:          time.Millisecond * 2300,
		},
	}

	trace := NewTrace(etw.KernelLoggerSession, etw.KernelTraceControlGUID, 0, cfg)
	require.NoError(t, trace.Start())
	require.True(t, trace.IsStarted())
	defer trace.Stop()
	require.Error(t, trace.Start())
	require.True(t, trace.IsRunning())
}
