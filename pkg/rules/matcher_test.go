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
package rules

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchers(t *testing.T) {
	var tests = []struct {
		name    string
		op      lexer.Token
		vals    []string
		matches []string
		rejects []string
		str     string
	}{
		{"eq", lexer.Eq, []string{"a.exe"}, []string{"a.exe"}, []string{"A.EXE", "b.exe", ""}, "= 'a.exe'"},
		{"ieq", lexer.IEq, []string{"a.exe"}, []string{"a.exe", "A.EXE"}, []string{"b.exe", "a.exe "}, "ieq 'a.exe'"},
		{"in", lexer.In, []string{"a", "b"}, []string{"a", "b"}, []string{"A", "c"}, "in ('a', 'b')"},
		{"iin", lexer.IIn, []string{"A", "b"}, []string{"a", "B", "A"}, []string{"c", "ab"}, "iin ('A', 'b')"},
		{"istartswith", lexer.IStartswith, []string{"C:\\Win", "d:"}, []string{"c:\\windows", "D:\\x"}, []string{"e:\\win", "x c:\\win"}, "istartswith ('c:\\win', 'd:')"},
		{"iendswith", lexer.IEndswith, []string{".EXE"}, []string{"a.exe", "A.Exe"}, []string{"a.exe.txt"}, "iendswith ('.exe')"},
		{"icontains", lexer.IContains, []string{"Cred", "tok"}, []string{"my CREDS", "xTOKx"}, []string{"password"}, "icontains ('cred', 'tok')"},
		{"imatches", lexer.IMatches, []string{"?:\\Windows\\*.dll", "*.sys"}, []string{"C:\\WINDOWS\\a.dll", "x.SYS"}, []string{"c:\\temp\\a.dll", "a.exe"}, "imatches ('?:\\Windows\\*.dll', '*.sys')"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, ok := NewMatcher(tt.op, tt.vals)
			require.True(t, ok)
			for _, v := range tt.matches {
				assert.True(t, m.Match(v), v)
			}
			for _, v := range tt.rejects {
				assert.False(t, m.Match(v), v)
			}
			assert.Equal(t, tt.str, m.String())
		})
	}
}

func TestMatcherTypes(t *testing.T) {
	var tests = []struct {
		op  lexer.Token
		typ Matcher
	}{
		{lexer.Eq, ExactMatcher{}},
		{lexer.IEq, ExactMatcher{}},
		{lexer.In, MembershipMatcher{}},
		{lexer.IIn, MembershipMatcher{}},
		{lexer.IStartswith, PrefixMatcher{}},
		{lexer.IEndswith, SuffixMatcher{}},
		{lexer.IContains, ContainsMatcher{}},
		{lexer.IMatches, PatternMatcher{}},
	}
	for _, tt := range tests {
		t.Run(tt.op.String(), func(t *testing.T) {
			m, ok := NewMatcher(tt.op, []string{"a"})
			require.True(t, ok)
			assert.IsType(t, tt.typ, m)
		})
	}
}

func TestNewMatcherRejectsUnsupported(t *testing.T) {
	for _, op := range []lexer.Token{lexer.Contains, lexer.Startswith, lexer.Endswith, lexer.Matches, lexer.Neq, lexer.Lt, lexer.And} {
		_, ok := NewMatcher(op, []string{"a"})
		assert.False(t, ok, op.String())
	}
	// no operands
	_, ok := NewMatcher(lexer.Eq, nil)
	assert.False(t, ok)
	// the equality operator accepts a single operand
	_, ok = NewMatcher(lexer.Eq, []string{"a", "b"})
	assert.False(t, ok)
}

func TestMatcherDoesNotAliasOperands(t *testing.T) {
	vals := []string{"A", "B"}
	m, ok := NewMatcher(lexer.IIn, vals)
	require.True(t, ok)
	vals[0] = "Z"
	assert.True(t, m.Match("a"))
	assert.False(t, m.Match("z"))
}
