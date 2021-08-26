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
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newFilters(paths ...string) Filters {
	return Filters{
		Rules{
			FromPaths: paths,
		},
	}
}

func TestLoadGroupsFromPaths(t *testing.T) {
	filters := Filters{
		Rules{
			FromPaths: []string{
				"_fixtures/filters/default.yml",
			},
		},
	}
	groups, err := filters.LoadGroups()
	require.NoError(t, err)
	require.Len(t, groups, 2)

	g1 := groups[0]
	assert.Equal(t, "internal network traffic", g1.Name)
	assert.True(t, g1.Enabled)
	assert.Equal(t, ktypes.Connect, g1.Selector.Type)
	assert.Equal(t, ExcludePolicy, g1.Policy)
	assert.Equal(t, AndRelation, g1.Relation)
	assert.Contains(t, g1.Tags, "TE")
	assert.Len(t, g1.FromStrings, 1)
	assert.Equal(t, "only network category", g1.FromStrings[0].Name)
	assert.Equal(t, "kevt.category = 'net'", g1.FromStrings[0].Def)

	g2 := groups[1]
	assert.Equal(t, "rouge processes", g2.Name)
	assert.True(t, g2.Enabled)
	assert.Equal(t, ktypes.Net, g2.Selector.Category)
	assert.Equal(t, IncludePolicy, g2.Policy)
	assert.Equal(t, OrRelation, g2.Relation)
	assert.Len(t, g2.FromStrings, 1)
	assert.Equal(t, "suspicious network ACTIVITY", g2.FromStrings[0].Name)
	assert.Equal(t, "kevt.category = 'net' and ps.name in ('at.exe', 'java.exe')", g2.FromStrings[0].Def)
}

func TestLoadGroupsFromURLs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/default.yml", func(w http.ResponseWriter, r *http.Request) {
		b, err := ioutil.ReadFile("_fixtures/filters/default.yml")
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
	}
	groups, err := filters.LoadGroups()
	require.NoError(t, err)
	require.Len(t, groups, 2)

	g1 := groups[0]
	assert.Equal(t, "internal network traffic", g1.Name)
	assert.True(t, g1.Enabled)
	assert.Equal(t, ktypes.Connect, g1.Selector.Type)
}

func TestLoadGroupsInvalidTemplates(t *testing.T) {
	var tests = []struct {
		filters Filters
		errMsg  string
	}{
		{newFilters("_fixtures/filters/invalid_filter_action.yml"), `invalid "suspicious network activity" filter action: syntax error in (suspicious network activity:1) at function "kil" not defined: function "kil" not defined`},
		{newFilters("_fixtures/filters/invalid_filter_action_values.yml"), `invalid "suspicious network activity" filter action: syntax error in (suspicious network activity:1:13) at <.Kevt.Pid>: can't evaluate field Pid in type *kevent.Kevent`},
		{newFilters("_fixtures/filters/filter_action_in_exclude_group.yml"), `"suspicious network activity" filter found in "rouge processes" group with exclude policy. Only groups with include policies can have filter actions`},
	}
	for i, tt := range tests {
		_, err := tt.filters.LoadGroups()
		if err.Error() != tt.errMsg {
			t.Errorf("%d. filter group error mismatch: exp=%s got=%v", i, tt.errMsg, err)
		}
	}
}

func TestLoadGroupsWithValues(t *testing.T) {
	filters := Filters{
		Rules{
			FromPaths: []string{
				"_fixtures/filters/values/default.yml",
			},
		},
	}
	groups, err := filters.LoadGroups()
	require.NoError(t, err)
	require.Len(t, groups, 2)

	g2 := groups[1]
	assert.Equal(t, "kevt.category = 'net' and ps.name in ('at.exe', 'java.exe', 'nc.exe')", g2.FromStrings[0].Def)
}
