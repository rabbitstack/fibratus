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
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func newConfig(fromFiles ...string) *config.Config {
	var kstreamConfig = config.KstreamConfig{
		EnableHandleKevents:   true,
		EnableNetKevents:      true,
		EnableRegistryKevents: true,
		EnableFileIOKevents:   true,
		EnableImageKevents:    true,
		EnableThreadKevents:   true,
	}
	c := &config.Config{
		Kstream: kstreamConfig,
		Filters: &config.Filters{
			Rules: config.Rules{
				FromPaths: fromFiles,
			},
		},
	}
	return c
}

func compileRules(t *testing.T, e *Engine) {
	rs, err := e.Compile()
	require.NoError(t, err)
	require.NotNil(t, rs)
}

func wrapProcessEvent(e *kevent.Kevent, fn func(*kevent.Kevent) (bool, error)) bool {
	match, err := fn(e)
	if err != nil {
		panic(err)
	}
	return match
}

func fireRules(t *testing.T, c *config.Config) bool {
	e := NewEngine(new(ps.SnapshotterMock), c)
	evt := &kevent.Kevent{
		Type:     ktypes.RecvTCPv4,
		Name:     "Recv",
		Tid:      2484,
		PID:      859,
		Category: ktypes.Net,
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
			kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
			kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
		Metadata: make(map[kevent.MetadataKey]any),
	}
	compileRules(t, e)
	return wrapProcessEvent(evt, e.ProcessEvent)
}

func TestCompileMergeFilters(t *testing.T) {
	psnap := new(ps.SnapshotterMock)
	e := NewEngine(psnap, newConfig("_fixtures/merged_filters/filter*.yml"))

	compileRules(t, e)

	assert.Len(t, e.filters, 2)

	tests := []struct {
		evt   *kevent.Kevent
		wants int
	}{
		{&kevent.Kevent{Type: ktypes.RecvUDPv6}, 3},
		{&kevent.Kevent{Type: ktypes.RecvTCPv4}, 3},
		{&kevent.Kevent{Type: ktypes.RecvTCPv4, Category: ktypes.Net}, 4},
		{&kevent.Kevent{Category: ktypes.Net}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.evt.Type.String(), func(t *testing.T) {
			assert.Len(t, e.findFilters(tt.evt), tt.wants)
		})
	}
}

func TestRunSimpleRules(t *testing.T) {
	var tests = []struct {
		config  *config.Config
		matches bool
	}{
		{newConfig("_fixtures/simple_matches.yml"), true},
		{newConfig("_fixtures/simple_matches/filter*.yml"), true},
	}

	for i, tt := range tests {
		matches := fireRules(t, tt.config)
		if matches != tt.matches {
			t.Errorf("%d. %v process rules mismatch: exp=%t got=%t", i, tt.config.Filters, tt.matches, matches)
		}
	}
}
