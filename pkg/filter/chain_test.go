/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package filter

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

func runChain(t *testing.T, c *config.Config) bool {
	chain := NewChain(c)

	kevt := &kevent.Kevent{
		Type: ktypes.Recv,
		Name: "Recv",
		Tid:  2484,
		PID:  859,
		Kparams: kevent.Kparams{
			kparams.NetDport: {Name: kparams.NetDport, Type: kparams.Uint16, Value: uint16(443)},
			kparams.NetSport: {Name: kparams.NetSport, Type: kparams.Uint16, Value: uint16(43123)},
			kparams.NetSIP:   {Name: kparams.NetSIP, Type: kparams.IPv4, Value: net.ParseIP("127.0.0.1")},
			kparams.NetDIP:   {Name: kparams.NetDIP, Type: kparams.IPv4, Value: net.ParseIP("216.58.201.174")},
		},
	}

	require.NoError(t, chain.Compile())
	return chain.Run(kevt)
}

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
			FromPaths: fromFiles,
		},
	}
	return c
}

func TestChainCompileMergeGroups(t *testing.T) {
	chain := NewChain(newConfig("_fixtures/merged_groups.yml"))
	require.NoError(t, chain.Compile())

	assert.Len(t, chain.filterGroups, 2)
	assert.Len(t, chain.filterGroups[ktypes.Recv.Hash()], 2)
	assert.Len(t, chain.filterGroups[ktypes.Net.Hash()], 1)
}

func TestChainRun(t *testing.T) {
	var tests = []struct {
		config  *config.Config
		matches bool
	}{
		{newConfig("_fixtures/exclude_policy_or.yml"), false},
		{newConfig("_fixtures/exclude_policy_and.yml"), false},
		{newConfig("_fixtures/exclude_policy_or_no_include_groups.yml"), true},
		{newConfig("_fixtures/exclude_policy_and_no_include_groups.yml"), true},
		{newConfig("_fixtures/exclude_policy_or_different_include_group.yml"), true},
		{newConfig("_fixtures/include_policy_or.yml"), true},
		{newConfig("_fixtures/include_policy_and.yml"), true},
		{newConfig("_fixtures/include_policy_and_not_matches.yml"), false},
	}

	for i, tt := range tests {
		matches := runChain(t, tt.config)
		if matches != tt.matches {
			t.Errorf("%d. %v filter chain mismatch: exp=%t got=%t", i, tt.config.Filters, tt.matches, matches)
		}
	}
}
