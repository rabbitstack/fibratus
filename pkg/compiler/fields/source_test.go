/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package fields

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFieldSource(t *testing.T) {
	var tests = []struct {
		field  Field
		source Source
	}{
		{"evt.pid", SourceEvent},
		{"kevt.name", SourceEvent},
		{"evt.arg", SourceEvent},
		{"ps.name", SourceProcess},
		{"ps.parent.name", SourceProcess},
		{"ps.ancestor", SourceProcess},
		// the namespace of the field isn't the source of its value
		{"ps.pe.imphash", SourcePE},
		{"ps.signature.trusted", SourcePE},
		{"pe.entrypoint", SourcePE},
		{"thread.start_address", SourceThread},
		{"file.path", SourceFile},
		{"module.path", SourceModule},
		{"image.name", SourceModule},
		{"dll.name", SourceModule},
		{"registry.key.path", SourceRegistry},
		{"net.dip", SourceNetwork},
		{"mem.address", SourceMemory},
		{"dns.name", SourceDNS},
		{"unknown.field", SourceNone},
		// a prefix has to end with the dot, so these don't match
		{"pse.name", SourceNone},
		{"filesystem.path", SourceNone},
		{"", SourceNone},
	}
	for _, tt := range tests {
		t.Run(string(tt.field), func(t *testing.T) {
			assert.Equal(t, tt.source, tt.field.Source())
		})
	}
}

func TestEveryDeclaredFieldHasSource(t *testing.T) {
	defs := Defs()
	require.NotEmpty(t, defs)
	for _, def := range defs {
		assert.NotEqual(t, SourceNone, def.Source, "%s has no source", def.Field)
		assert.Less(t, int(def.Source), int(NumSources))
	}
}

func TestLookup(t *testing.T) {
	def, ok := Lookup(EvtPID)
	require.True(t, ok)
	assert.Equal(t, EvtPID, def.Field)
	assert.Equal(t, SourceEvent, def.Source)
	assert.Equal(t, EvtPID.Type(), def.Type)

	_, ok = Lookup(Field("evt.no.such.field"))
	assert.False(t, ok)
}

func TestSourceString(t *testing.T) {
	assert.Equal(t, "pe", SourcePE.String())
	assert.Equal(t, "none", SourceNone.String())
	assert.Equal(t, "unknown", NumSources.String())
}
