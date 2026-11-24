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

package eval

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBoundFieldsConfigureExtractor(t *testing.T) {
	ev, err := NewEvaluator(uuid.New().String(), `sequence
	|evt.name = 'CreateProcess'| as e1
	|evt.name = 'CreateFile' and ps.sid = $e1.ps.pe.imphash|`)
	require.NoError(t, err)

	// the bound field is recorded, so the accessors can be configured for it
	bound := ev.GetBoundFields()
	require.Len(t, bound, 1)
	assert.Equal(t, "ps.pe.imphash", bound[0].String())

	// but it's never extracted from the evaluated event
	for _, f := range ev.GetFields() {
		assert.NotEqual(t, "ps.pe.imphash", f.String())
	}
	for _, f := range ev.extractor.fields {
		assert.NotEqual(t, "ps.pe.imphash", f.String())
	}
}

func TestBoundFieldDoesNotShadowUnboundField(t *testing.T) {
	ev, err := NewEvaluator(uuid.New().String(), `sequence
	|evt.name = 'CreateProcess' and ps.name = 'cmd.exe'| as e1
	|evt.name = 'CreateFile' and ps.name = $e1.ps.name|`)
	require.NoError(t, err)

	assert.Contains(t, fieldNames(ev), "ps.name")
	require.Len(t, ev.GetBoundFields(), 1)
	assert.Equal(t, "ps.name", ev.GetBoundFields()[0].String())
	assert.Len(t, ev.extractor.fields, len(ev.GetFields()))
}
