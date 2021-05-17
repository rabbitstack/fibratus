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
	"testing"
)

func TestLoadGroups(t *testing.T) {
	filters := Filters{
		FromPaths: []string{
			"_fixtures/filters/default.yml",
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

func TestLoadGroupsInvalidFilterAction(t *testing.T) {
	filters := Filters{
		FromPaths: []string{
			"_fixtures/filters/invalid_filter_action.yml",
		},
	}
	_, err := filters.LoadGroups()
	require.NoError(t, err)
}
