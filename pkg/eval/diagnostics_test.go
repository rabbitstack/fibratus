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

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func warnedFields(ws []FieldWarning) []string {
	var names []string
	for _, w := range ws {
		names = append(names, string(w.Field))
	}
	return names
}

func TestFieldWarnings(t *testing.T) {
	enabledAll := func(fields.Source) bool { return true }
	noFile := func(s fields.Source) bool { return s != fields.SourceFile }

	tests := []struct {
		name    string
		expr    string
		enabled func(fields.Source) bool
		want    []string
	}{
		{"fields of the scope", fileScoped + ` and file.path = '/tmp/x' and ps.name = 'bash'`, enabledAll, nil},
		{"a nil predicate enables everything", fileScoped + ` and file.path = '/tmp/x'`, nil, nil},
		{"field of another category", fileScoped + ` and net.dport = 80`, enabledAll, []string{"net.dport"}},
		{"field of another category in an or branch", fileScoped + ` and (file.path = '/tmp/x' or net.dport = 80)`, enabledAll, []string{"net.dport"}},
		{"evt fields serve every event", fileScoped + ` and evt.pid = 1`, enabledAll, nil},
		{"disabled source", fileScoped + ` and file.path = '/tmp/x'`, noFile, []string{"file.path"}},
		{"disabled source of an unrelated field", fileScoped + ` and ps.name = 'bash'`, noFile, nil},
		{"fields of a union of types", `evt.name in ('` + fileEvt + `', '` + netEvt + `') and (file.path = '/tmp/x' or net.dport = 80)`, enabledAll, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewProgram("t", tt.expr)
			require.NoError(t, err)
			assert.Equal(t, tt.want, warnedFields(p.FieldWarnings(tt.enabled)))
		})
	}
}

func TestFieldWarningExplainsTheScope(t *testing.T) {
	p, err := NewProgram("t", fileScoped+` and net.dport = 80`)
	require.NoError(t, err)
	ws := p.FieldWarnings(nil)
	require.Len(t, ws, 1)
	assert.Contains(t, ws[0].String(), "net.dport")
	assert.Contains(t, ws[0].String(), fileEvt)
}

func TestFieldWarningForFieldNobodyServes(t *testing.T) {
	// the field is declared on Windows only, and no source ever served it
	if _, declared := fields.Lookup(fields.PsDTB); !declared {
		t.Skip("ps.dtb isn't declared on this platform")
	}
	p, err := NewProgram("t", `evt.name = 'x' and ps.dtb = 'ffff'`)
	require.NoError(t, err)
	assert.Equal(t, []string{"ps.dtb"}, warnedFields(p.FieldWarnings(nil)))
}
