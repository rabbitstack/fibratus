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

func TestLoadRulesFromPaths(t *testing.T) {
	filters := Filters{
		Rules{
			FromPaths: []string{
				"_fixtures/filters/default.yml",
				"_fixtures/filters/default1.yml",
			},
		},
		Macros{FromPaths: nil},
		false,
		map[string]*Macro{},
		[]*FilterConfig{},
	}
	err := filters.LoadFilters()
	require.NoError(t, err)
	require.Len(t, filters.filters, 2)

	f1 := filters.filters[0]
	assert.Equal(t, "only network category", f1.Name)
	assert.Equal(t, "313933e7-8eb9-45d9-81af-0305fee70e29", f1.ID)
	assert.Equal(t, "1.0.0", f1.Version)
	assert.True(t, *f1.Enabled)
	assert.Contains(t, f1.Tags, "TE")
	assert.Equal(t, "kevt.category = 'net'", f1.Condition)
	assert.Equal(t, "this rule matches all network signals", f1.Description)
	assert.Equal(t, "low", f1.Severity)
	assert.Equal(t, "`%ps.exe` attempted to reach out to `%net.sip` IP address\n", f1.Output)
	assert.NotNil(t, f1.Action)
	assert.Contains(t, f1.References, "ref2")
	assert.NotEmpty(t, f1.Notes)

	acts, err := f1.DecodeActions()
	require.NoError(t, err)
	require.IsType(t, KillAction{}, acts[0])
	require.IsType(t, IsolateAction{}, acts[1])

	isolate := acts[1].(IsolateAction)
	require.Len(t, isolate.Whitelist, 2)
	require.Contains(t, isolate.Whitelist, net.ParseIP("127.0.0.1"))

	assert.Equal(t, "2.0.0", f1.MinEngineVersion)

	f2 := filters.filters[1]
	assert.False(t, f2.IsDisabled())
	assert.Equal(t, "suspicious network ACTIVITY", f2.Name)
	assert.Equal(t, "kevt.category = 'net' and ps.name in ('at.exe', 'java.exe')", f2.Condition)
}

func TestLoadRulesFromPathsWithTemplate(t *testing.T) {
	filters := Filters{
		Rules{
			FromPaths: []string{
				"_fixtures/filters/default-with-template.yml",
			},
		},
		Macros{FromPaths: nil},
		false,
		map[string]*Macro{},
		[]*FilterConfig{},
	}
	err := filters.LoadFilters()
	require.NoError(t, err)
	require.Len(t, filters.filters, 1)

	f1 := filters.filters[0]
	assert.Equal(t, "ALL NETWORK EVENTS\n", f1.Output)
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
		false,
		map[string]*Macro{},
		[]*FilterConfig{},
	}
	err = filters.LoadFilters()
	require.NoError(t, err)
	require.Len(t, filters.filters, 1)

	f1 := filters.filters[0]
	assert.Equal(t, "only network category", f1.Name)
	assert.True(t, *f1.Enabled)
	assert.Contains(t, f1.Tags, "TE")
	assert.Equal(t, "kevt.category = 'net'", f1.Condition)
	assert.Equal(t, "this rule matches all network signals", f1.Description)
	assert.Equal(t, "low", f1.Severity)
	assert.Equal(t, "`%ps.exe` attempted to reach out to `%net.sip` IP address\n", f1.Output)
	assert.NotNil(t, f1.Action)

	acts, err := f1.DecodeActions()
	require.NoError(t, err)
	require.IsType(t, KillAction{}, acts[0])

	assert.Equal(t, "2.0.0", f1.MinEngineVersion)
}
