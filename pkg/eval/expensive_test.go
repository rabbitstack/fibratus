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

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/compiler/parser"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsExpensive(t *testing.T) {
	for _, f := range []fields.Field{
		fields.PsSignatureTrusted, fields.FileIsDLL, fields.NetDIPNames, fields.ThreadCallstackSummary,
		"ps.pe.imphash", "pe.is_dll", "module.signature.exists",
	} {
		assert.True(t, IsExpensive(f), f)
	}
	for _, f := range []fields.Field{fields.EvtName, fields.PsName, fields.FilePath, fields.NetDIP, fields.RegistryPath} {
		assert.False(t, IsExpensive(f), f)
	}
}

func TestLintOrder(t *testing.T) {
	// evt.host stands in for an expensive field, since the expensive
	// fields are Windows only
	expensive := func(f fields.Field) bool { return f == fields.EvtHost }

	tests := []struct {
		expr string
		want []OrderWarning
	}{
		{`evt.name = 'a' and evt.host = 'b'`, nil},
		{`evt.host = 'b' and evt.name = 'a'`, []OrderWarning{{fields.EvtHost, fields.EvtName}}},
		{`evt.host = 'b' or evt.name = 'a'`, []OrderWarning{{fields.EvtHost, fields.EvtName}}},
		{`evt.host = 'b' and evt.host = 'c'`, nil},
		{`evt.host = 'b' and evt.pid = 1 and evt.name = 'a'`, []OrderWarning{{fields.EvtHost, fields.EvtPID}}},
		{`evt.pid = 1 and (evt.host = 'b' and evt.name = 'a')`, []OrderWarning{{fields.EvtHost, fields.EvtName}}},
		{`(evt.host = 'b' or evt.pid = 1) and evt.name = 'a'`, []OrderWarning{{fields.EvtHost, fields.EvtName}, {fields.EvtHost, fields.EvtPID}}},
		{`evt.host = 'b' and true`, nil},
		{`evt.name = 'a'`, nil},
		{`not (evt.host = 'b' and evt.name = 'a')`, []OrderWarning{{fields.EvtHost, fields.EvtName}}},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			expr, err := parser.Parse(tt.expr)
			require.NoError(t, err)
			var got []OrderWarning
			lintOrder(expr, expensive, func(w OrderWarning) { got = append(got, w) })
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestLintOrderSequenceSteps(t *testing.T) {
	expensive := func(f fields.Field) bool { return f == fields.EvtHost }
	expr, err := parser.Parse(`sequence
	|evt.host = 'a' and evt.name = 'b'| by evt.pid
	|evt.name = 'c'| by evt.pid
	`)
	require.NoError(t, err)
	_, ok := expr.(*ast.SequenceExpr)
	require.True(t, ok)
	var got []OrderWarning
	lintOrder(expr, expensive, func(w OrderWarning) { got = append(got, w) })
	assert.Equal(t, []OrderWarning{{fields.EvtHost, fields.EvtName}}, got)
}
