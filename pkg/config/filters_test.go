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

package config

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func newFilters(paths ...string) Filters {
	return Filters{
		Rules{
			FromPaths: paths,
		},
		Macros{FromPaths: nil},
		map[string]*Macro{},
		[]FilterGroup{},
	}
}

func TestLoadGroupsFromPaths(t *testing.T) {
	filters := Filters{
		Rules{
			FromPaths: []string{
				"_fixtures/filters/default.yml",
			},
		},
		Macros{FromPaths: nil},
		map[string]*Macro{},
		[]FilterGroup{},
	}
	err := filters.LoadGroups()
	require.NoError(t, err)
	require.Len(t, filters.groups, 2)

	g1 := filters.groups[0]
	assert.Equal(t, "internal network traffic", g1.Name)
	assert.True(t, *g1.Enabled)
	assert.Contains(t, g1.Tags, "TE")
	assert.Len(t, g1.Rules, 1)
	assert.Equal(t, "only network category", g1.Rules[0].Name)
	assert.Equal(t, "kevt.category = 'net'", g1.Rules[0].Condition)
	assert.Equal(t, "this rule matches all network signals", g1.Rules[0].Description)
	assert.Equal(t, "low", g1.Rules[0].Severity)
	assert.Equal(t, "`%ps.exe` attempted to reach out to `%net.sip` IP address\n", g1.Rules[0].Output)
	assert.NotNil(t, g1.Rules[0].Action)

	acts, err := g1.Rules[0].DecodeActions()
	require.NoError(t, err)
	require.IsType(t, KillAction{}, acts[0])

	assert.Equal(t, "ps.pid", acts[0].(KillAction).Pid)

	g2 := filters.groups[1]
	assert.Equal(t, "rouge processes", g2.Name)
	assert.True(t, *g2.Enabled)
	assert.Len(t, g2.Rules, 1)
	assert.Equal(t, "suspicious network ACTIVITY", g2.Rules[0].Name)
	assert.Equal(t, "kevt.category = 'net' and ps.name in ('at.exe', 'java.exe')", g2.Rules[0].Condition)
}

func TestLoadGroupsFromPathsNewAttributes(t *testing.T) {
	filters := Filters{
		Rules{
			FromPaths: []string{
				"_fixtures/filters/default-new-attributes.yml",
			},
		},
		Macros{FromPaths: nil},
		map[string]*Macro{},
		[]FilterGroup{},
	}
	err := filters.LoadGroups()
	require.NoError(t, err)
	require.Len(t, filters.groups, 2)

	g1 := filters.groups[0]
	assert.Equal(t, "internal network traffic", g1.Name)
	assert.False(t, *g1.Enabled)
	assert.Contains(t, g1.Tags, "TE")
	assert.Len(t, g1.Rules, 1)
	assert.Equal(t, "only network category", g1.Rules[0].Name)

	g2 := filters.groups[1]
	assert.Equal(t, "rouge processes", g2.Name)
	assert.Nil(t, g2.Enabled)
	assert.False(t, g2.IsDisabled())
	assert.Len(t, g2.Rules, 1)
	assert.Equal(t, "suspicious network ACTIVITY", g2.Rules[0].Name)
	assert.Equal(t, "kevt.category = 'net' and ps.name in ('at.exe', 'java.exe')", g2.Rules[0].Condition)
}

func TestLoadGroupsFromURLs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/default.yml", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile("_fixtures/filters/default.yml")
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(b)
	})

	l, err := net.Listen("tcp", "127.0.0.1:3231")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(mux)
	srv.Listener = l
	srv.Start()
	defer srv.Close()

	filters := Filters{
		Rules{
			FromURLs: []string{
				"http://localhost:3231/default.yml",
			},
		},
		Macros{FromPaths: nil},
		map[string]*Macro{},
		[]FilterGroup{},
	}
	err = filters.LoadGroups()
	require.NoError(t, err)
	require.Len(t, filters.groups, 2)

	g1 := filters.groups[0]
	assert.Equal(t, "internal network traffic", g1.Name)
	assert.True(t, *g1.Enabled)
}

func TestLoadGroupsInvalidTemplates(t *testing.T) {
	var tests = []struct {
		filters Filters
		errMsg  string
	}{
		{newFilters("_fixtures/filters/invalid_filter_action.yml"), `invalid "suspicious network activity" rule action: syntax error in (suspicious network activity:1) at function "kil" not defined: function "kil" not defined`},
		{newFilters("_fixtures/filters/invalid_filter_action_values.yml"), `invalid "suspicious network activity" rule action: syntax error in (suspicious network activity:1:13) at <.Kevt.Pid>: can't evaluate field Pid in type *kevent.Kevent`},
	}
	for i, tt := range tests {
		err := tt.filters.LoadGroups()
		if err.Error() != tt.errMsg {
			t.Errorf("%d. filter group error mismatch: exp=%s got=%v", i, tt.errMsg, err)
		}
	}
}
