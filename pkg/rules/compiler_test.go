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
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/version"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCompile(t *testing.T) {
	c := newCompiler(new(ps.SnapshotterMock), newConfig("_fixtures/default/*.yml"))
	filters, rs, err := c.compile()
	require.NoError(t, err)
	require.NotNil(t, rs)
	require.Len(t, filters, 6)

	assert.True(t, rs.HasImageEvents)
	assert.True(t, rs.HasProcEvents)
	assert.False(t, rs.HasMemEvents)
	assert.False(t, rs.HasAuditAPIEvents)
	assert.True(t, rs.HasDNSEvents)
	assert.Contains(t, rs.UsedEvents, ktypes.CreateProcess)
	assert.Contains(t, rs.UsedEvents, ktypes.LoadImage)
	assert.Contains(t, rs.UsedEvents, ktypes.QueryDNS)
	assert.Contains(t, rs.UsedEvents, ktypes.ConnectTCPv4)
	assert.Contains(t, rs.UsedEvents, ktypes.ConnectTCPv6)
}

func TestCompileMinEngineVersion(t *testing.T) {
	var tests = []struct {
		rules string
		ver   string
		e     string
	}{
		{"_fixtures/min_engine_version/fail/*.yml", "2.0.0", `rule "accept events where source port = 44123" needs engine version [2.2.0] but current version is [2.0.0]`},
		{"_fixtures/min_engine_version/ok/*.yml", "2.0.0", ""},
	}

	for _, tt := range tests {
		t.Run(tt.rules, func(t *testing.T) {
			c := newCompiler(new(ps.SnapshotterMock), newConfig(tt.rules))
			version.Set(tt.ver)
			_, _, err := c.compile()
			if err != nil && tt.e == "" {
				require.Error(t, err)
			}
			if err != nil {
				require.EqualError(t, err, tt.e)
			}
		})
	}
}
