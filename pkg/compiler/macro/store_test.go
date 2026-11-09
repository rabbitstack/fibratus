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
package macro

import (
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/parser"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func expr(id, e string) *policy.MacroDef { return &policy.MacroDef{ID: id, Expression: e} }
func list(id string, v ...string) *policy.MacroDef {
	return &policy.MacroDef{ID: id, Values: v}
}

func parseWithMacros(expr string, macroStore *Store) (ast.Expr, error) {
	e, err := parser.Parse(expr, parser.WithMacroResolver(macroStore))
	if err != nil {
		return nil, err
	}
	return macroStore.Expand(e)
}

func mustStore(t *testing.T, macros ...*policy.MacroDef) *Store {
	t.Helper()
	s, err := NewStore(macros...)
	require.NoError(t, err)
	return s
}

func TestExpandMacros(t *testing.T) {
	var tests = []struct {
		name     string
		macros   []*policy.MacroDef
		expr     string
		expected string
		err      string
	}{
		{
			"expression macro",
			[]*policy.MacroDef{expr("spawn_process", "evt.name = 'CreateProcess'")},
			"spawn_process and ps.name in ('cmd.exe', 'powershell.exe')",
			"evt.name = CreateProcess AND ps.name IN (cmd.exe, powershell.exe)",
			"",
		},
		{
			"unknown macro is a syntax error",
			[]*policy.MacroDef{expr("span_process", "evt.name = 'CreateProcess'")},
			"spawn_process and ps.name in ('cmd.exe', 'powershell.exe')",
			"",
			"expected field, bound field, string, number, bool, ip, function",
		},
		{
			"expression and list macros",
			[]*policy.MacroDef{
				expr("spawn_process", "evt.name = 'CreateProcess'"),
				list("command_clients", "cmd.exe", "pwsh.exe"),
			},
			"spawn_process and ps.name in command_clients",
			"evt.name = CreateProcess AND ps.name IN (cmd.exe, pwsh.exe)",
			"",
		},
		{
			"macros referencing macros and list with wildcards",
			[]*policy.MacroDef{
				expr("rename", "evt.name = 'RenameFile'"),
				expr("remove", "evt.name = 'DeleteFile'"),
				expr("modify", "rename or remove"),
				list("wcm_files", `?:\Users\*\AppData\*\Microsoft\Credentials\*`),
			},
			"(modify) and file.name imatches wcm_files",
			`(evt.name = RenameFile OR evt.name = DeleteFile) AND file.name IMATCHES (?:\Users\*\AppData\*\Microsoft\Credentials\*)`,
			"",
		},
		{
			"unknown identifier next to a function call",
			[]*policy.MacroDef{
				expr("rename", "evt.name = 'RenameFile'"),
				expr("remove", "evt.name = 'DeleteFile'"),
				expr("modify", "rename or remove"),
			},
			"entropy(file.name) > 0.22 and ren",
			"",
			"field, bound field, string, number, bool, ip, function",
		},
		{
			"macro next to a function call",
			[]*policy.MacroDef{
				expr("rename", "evt.name = 'RenameFile'"),
				expr("remove", "evt.name = 'DeleteFile'"),
			},
			"entropy(file.name) > 0.22 and rename",
			"entropy(file.name) > 2.2e-01 AND evt.name = RenameFile",
			"",
		},
		{
			"deeply nested macros as the root",
			[]*policy.MacroDef{
				expr("rename", "evt.name = 'RenameFile'"),
				expr("remove", "evt.name = 'DeleteFile'"),
				expr("create", "evt.name = 'CreateFile' and file.operation = 'create'"),
				expr("modify", "rename or remove"),
				expr("change_fs", "modify or (create)"),
			},
			"change_fs",
			"evt.name = RenameFile OR evt.name = DeleteFile OR (evt.name = CreateFile AND file.operation = create)",
			"",
		},
		{
			"negated macro",
			[]*policy.MacroDef{expr("spawn_process", "evt.name = 'CreateProcess'")},
			"not spawn_process",
			"NOT evt.name = CreateProcess",
			"",
		},
		{
			"infix negated list macro",
			[]*policy.MacroDef{list("shells", "cmd.exe", "pwsh.exe")},
			"ps.name not in shells",
			"NOT ps.name IN (cmd.exe, pwsh.exe)",
			"",
		},
		{
			"macros are declared in any order",
			[]*policy.MacroDef{
				expr("outer", "inner and ps.name = 'a.exe'"),
				expr("inner", "evt.name = 'CreateProcess'"),
			},
			"outer",
			"evt.name = CreateProcess AND ps.name = a.exe",
			"",
		},
		{
			"the same macro is used multiple times",
			[]*policy.MacroDef{expr("m", "evt.name = 'CreateFile'")},
			"m and (m or file.name = 'a')",
			"evt.name = CreateFile AND (evt.name = CreateFile OR file.name = a)",
			"",
		},
		{
			"list macro as an operand of a logical operator",
			[]*policy.MacroDef{list("shells", "cmd.exe")},
			"ps.name = 'a.exe' and shells",
			"",
			`list macro "shells" can only be used as the right operand`,
		},
		{
			"list macro as the left operand",
			[]*policy.MacroDef{list("shells", "cmd.exe")},
			"shells in ('a')",
			"",
			`list macro "shells" can only be used as the right operand`,
		},
		{
			"expression macro in place of a list",
			[]*policy.MacroDef{expr("m", "evt.name = 'CreateFile'")},
			"ps.name in m",
			"",
			"expected '('",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewStore(tt.macros...)
			require.NoError(t, err)

			e, err := parseWithMacros(tt.expr, s)
			if tt.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, e.String())
		})
	}
}

func TestNewStoreErrors(t *testing.T) {
	var tests = []struct {
		name   string
		macros []*policy.MacroDef
		err    string
	}{
		{
			"syntax error in macro body",
			[]*policy.MacroDef{
				expr("spawn_process", "evt.nnname = 'CreateProcess'"),
				list("command_clients", "cmd.exe", "pwsh.exe"),
			},
			`syntax error in "spawn_process" macro`,
		},
		{"duplicate macro", []*policy.MacroDef{expr("m", "evt.name = 'a'"), expr("m", "evt.name = 'b'")}, `duplicate macro "m"`},
		{"invalid definition", []*policy.MacroDef{{ID: "m"}}, "either expression or list"},
		{"self reference", []*policy.MacroDef{expr("a", "a and evt.name = 'x'")}, "macro cycle detected: a -> a"},
		{
			"mutual reference",
			[]*policy.MacroDef{expr("a", "b"), expr("b", "a")},
			"macro cycle detected: a -> b -> a",
		},
		{
			"indirect cycle",
			[]*policy.MacroDef{expr("a", "b and evt.name = 'x'"), expr("b", "c"), expr("c", "evt.name = 'y' or a")},
			"macro cycle detected: a -> b -> c -> a",
		},
		{
			"list macro used as an expression in a macro body",
			[]*policy.MacroDef{list("shells", "cmd.exe"), expr("m", "evt.name = 'x' and shells")},
			`list macro "shells" can only be used as the right operand`,
		},
		{
			"cycle in unused macro",
			[]*policy.MacroDef{expr("used", "evt.name = 'a'"), expr("x", "y"), expr("y", "x")},
			"macro cycle detected",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewStore(tt.macros...)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.err)
		})
	}
}

// macroChain builds n macros where every macro references the previous one.
// The deepest macro comes first, so the first expansion walks the whole chain.
func macroChain(n int) []*policy.MacroDef {
	macros := []*policy.MacroDef{expr("m0", "evt.name = 'CreateFile'")}
	for i := 1; i < n; i++ {
		macros = append(macros, expr(fmt.Sprintf("m%d", i), fmt.Sprintf("m%d", i-1)))
	}
	slices.Reverse(macros)
	return macros
}

func TestNewStoreDepthLimit(t *testing.T) {
	_, err := NewStore(macroChain(maxDepth + 3)...)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum expansion depth")

	// a chain within the limit is fine
	s, err := NewStore(macroChain(maxDepth - 2)...)
	require.NoError(t, err)
	e, err := parseWithMacros(fmt.Sprintf("m%d", maxDepth-3), s)
	require.NoError(t, err)
	assert.Equal(t, "evt.name = CreateFile", e.String())
}

func TestStoreAccessors(t *testing.T) {
	s := mustStore(t, expr("a", "evt.name = 'x'"), list("b", "1", "2"), expr("c", "a"))

	assert.Equal(t, 3, s.Len())
	assert.True(t, s.IsMacro("a"))
	assert.True(t, s.IsMacro("b"))
	assert.False(t, s.IsMacro("z"))
	assert.False(t, s.IsListMacro("a"))
	assert.True(t, s.IsListMacro("b"))
	assert.False(t, s.IsListMacro("z"))
	assert.True(t, s.Contains("c"))
	assert.False(t, s.Contains("z"))
	assert.Equal(t, "b", s.Get("b").ID)
	assert.Nil(t, s.Get("z"))

	// declaration order is preserved
	ids := make([]string, 0)
	for _, m := range s.List() {
		ids = append(ids, m.ID)
	}
	assert.Equal(t, []string{"a", "b", "c"}, ids)
}

func TestNilStore(t *testing.T) {
	var s *Store
	assert.False(t, s.IsMacro("a"))
	assert.False(t, s.IsListMacro("a"))
	assert.False(t, s.Contains("a"))
	assert.Nil(t, s.Get("a"))
	assert.Nil(t, s.List())
	assert.Equal(t, 0, s.Len())

	// a nil store parses expressions without macros
	e, err := parseWithMacros("evt.name = 'CreateFile'", s)
	require.NoError(t, err)
	assert.Equal(t, "evt.name = CreateFile", e.String())

	// and macros are plain unknown identifiers
	_, err = parseWithMacros("evt.name = 'CreateFile' and spawn_process", s)
	require.Error(t, err)
}

func TestEmptyStore(t *testing.T) {
	s := mustStore(t)
	e, err := parseWithMacros("ps.name = 'cmd.exe'", s)
	require.NoError(t, err)
	assert.Equal(t, "ps.name = cmd.exe", e.String())
}

func TestExpandSequence(t *testing.T) {
	s := mustStore(t,
		expr("spawn_process", "evt.name = 'CreateProcess'"),
		expr("create_file", "evt.name = 'CreateFile'"),
		list("shells", "cmd.exe", "powershell.exe"),
	)
	e, err := parseWithMacros(`sequence
		|spawn_process and ps.name in shells| by ps.uuid
		|create_file| by ps.uuid
	`, s)
	require.NoError(t, err)

	seq, ok := e.(*ast.SequenceExpr)
	require.True(t, ok)
	require.Len(t, seq.Steps, 2)
	assert.Equal(t, "evt.name = CreateProcess AND ps.name IN (cmd.exe, powershell.exe)", seq.Steps[0].Expr.String())
	assert.Equal(t, "evt.name = CreateFile", seq.Steps[1].Expr.String())
}

func TestExpandedMacroBodiesAreShared(t *testing.T) {
	s := mustStore(t, expr("m", "evt.name = 'CreateFile' and file.name = 'a'"))

	e1, err := parseWithMacros("m", s)
	require.NoError(t, err)
	e2, err := parseWithMacros("m and ps.name = 'x'", s)
	require.NoError(t, err)

	// the macro is parsed once. All the use sites reference
	// the same expanded body
	assert.Same(t, e1, e2.(*ast.BinaryExpr).LHS)
	assert.Same(t, e1, s.expanded["m"])
}

func TestListMacroValuesAreCopiedPerUseSite(t *testing.T) {
	s := mustStore(t, list("shells", "cmd.exe", "pwsh.exe"))

	e1, err := parseWithMacros("ps.name in shells", s)
	require.NoError(t, err)
	e2, err := parseWithMacros("ps.name in shells", s)
	require.NoError(t, err)

	l1 := e1.(*ast.BinaryExpr).RHS.(*ast.ListLiteral)
	l2 := e2.(*ast.BinaryExpr).RHS.(*ast.ListLiteral)

	l1.Values[0] = "changed"
	assert.Equal(t, "cmd.exe", l2.Values[0])
	assert.Equal(t, "cmd.exe", s.Get("shells").Values[0])
}

func TestExpandUnknownMacroReference(t *testing.T) {
	// a reference to a macro that is not in the store
	// can only come from an expression built by hand
	s := mustStore(t)
	_, err := s.Expand(&ast.MacroRef{Name: "ghost"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unknown macro "ghost"`)
}

func TestStoreConcurrentUse(t *testing.T) {
	s := mustStore(t,
		expr("rename", "evt.name = 'RenameFile'"),
		expr("remove", "evt.name = 'DeleteFile'"),
		expr("modify", "rename or remove"),
		list("shells", "cmd.exe", "pwsh.exe"),
	)

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				e, err := parseWithMacros("modify and ps.name in shells", s)
				assert.NoError(t, err)
				assert.Equal(t, "evt.name = RenameFile OR evt.name = DeleteFile AND ps.name IN (cmd.exe, pwsh.exe)", e.String())
			}
		}()
	}
	wg.Wait()
}
