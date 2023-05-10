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
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestStartTraces(t *testing.T) {
	var tests = []struct {
		name         string
		cfg          config.KstreamConfig
		wantSessions int
		wantFlags    []etw.EventTraceFlags
	}{
		{"start kernel logger session",
			config.KstreamConfig{
				EnableThreadKevents: true,
				EnableNetKevents:    true,
				EnableFileIOKevents: true,
				BufferSize:          1024,
				FlushTimer:          time.Millisecond * 2300,
			},
			1,
			[]etw.EventTraceFlags{0x6010203, 0},
		},
		{"start kernel logger and audit api sessions",
			config.KstreamConfig{
				EnableThreadKevents:   true,
				EnableNetKevents:      true,
				EnableFileIOKevents:   true,
				EnableHandleKevents:   true,
				EnableRegistryKevents: true,
				BufferSize:            1024,
				FlushTimer:            time.Millisecond * 2300,
				EnableAuditAPIEvents:  true,
			},
			2,
			[]etw.EventTraceFlags{0x6030203, 0x80000040},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctrl := NewController(tt.cfg)
			require.NoError(t, ctrl.Start())
			defer ctrl.Close()
			assert.Equal(t, tt.wantSessions, len(ctrl.traces))
			for _, trace := range ctrl.traces {
				require.True(t, trace.Handle.IsValid())
				require.NoError(t, etw.ControlTrace(0, trace.Name, trace.GUID, etw.Query))
				if tt.wantFlags != nil && trace.IsKernelLogger() {
					flags, err := etw.GetTraceSystemFlags(trace.Handle)
					require.NoError(t, err)
					// check enabled system event flags
					require.Equal(t, tt.wantFlags[0], flags[0])
					require.Equal(t, tt.wantFlags[1], flags[4])
				}
			}
		})
	}
}

func TestRestartTrace(t *testing.T) {
	cfg := config.KstreamConfig{
		EnableThreadKevents: true,
		EnableNetKevents:    true,
		EnableFileIOKevents: true,
		BufferSize:          1024,
		FlushTimer:          time.Millisecond * 2300,
	}
	ctrl := NewController(cfg)
	require.NoError(t, ctrl.Start())
	require.NoError(t, ctrl.Start())
	require.NoError(t, etw.ControlTrace(0, ctrl.traces[0].Name, ctrl.traces[0].GUID, etw.Query))
	require.NoError(t, ctrl.Close())
}
