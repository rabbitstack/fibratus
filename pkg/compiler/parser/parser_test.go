/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package parser

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParser(t *testing.T) {
	var tests = []struct {
		expr string
		err  error
	}{
		{expr: "ps.name = 'cmd.exe'"},
		{expr: "ps.name != 'cmd.exe'"},
		{expr: "ps.name <> 'cmd.exe'"},
		{expr: "ps.name <> 'cmd.exe", err: errors.New("ps.name <> 'cmd.exe\n╭─────────^\n|\n|\n╰─────────────────── expected a valid string but bad string or escape found")},
		{expr: "ps.name = 123"},
		{expr: "net.dip = 172.17.0.9"},
		{expr: "net.dip = 172.17.0.9 and net.dip in ('172.15.9.2')"},
		{expr: "net.dip = 172.17.0.9 and (net.dip not in ('172.15.9.2'))"},

		{expr: "net.dip = 172.17.0", err: errors.New("net.dip = 172.17.0\n╭─────────^\n|\n|\n╰─────────────────── expected a valid IP address")},

		{expr: "ps.name = 'cmd.exe' OR ps.name contains 'svc'"},
		{expr: "ps.name = 'cmd.exe' AND (ps.name contains 'svc' OR ps.name != 'lsass')"},
		{expr: "ps.name = 'cmd.exe' AND (ps.name contains 'svc' OR ps.name != 'lsass'", err: errors.New("ps.name = 'cmd.exe' AND (ps.name contains 'svc' OR ps.name != 'lsass'\n╭─────────────────────────────────────────────────────────────────────^\n|\n|\n╰─────────────────── expected ')'")},

		{expr: "ps.name = 'cmd.exe' OR ((ps.name contains 'svc' AND ps.name != 'lsass') AND ps.ppid != 1)"},

		{expr: "ps.name = 'cmd.exe' OR ((ps.name contains 'svc' AND ps.name != 'lsass' AND ps.ppid != 1)", err: errors.New("ps.name = 'cmd.exe' OR ((ps.name contains 'svc' AND ps.name != 'lsass' AND ps.ppid != 1)\n╭────────────────────────────────────────────────────────────────────────────────────────^\n|\n|\n╰─────────────────── expected ')'")},

		{expr: "ps.name = 'cmd.exe' OR ((ps.name contains 'svc' AND ps.name != 'lsass') AND ps.ppid != 1", err: errors.New("ps.name = 'cmd.exe' OR ((ps.name contains 'svc' AND ps.name != 'lsass') AND ps.ppid != 1\n╭────────────────────────────────────────────────────────────────────────────────────────^\n|\n|\n╰─────────────────── expected ')'")},

		{expr: "ps.none = 'cmd.exe'", err: errors.New("ps.none = 'cmd.exe'\n╭^\n|\n|\n╰─────────────────── expected field, bound field, string, number, bool, ip, function")},

		{expr: "ps.name = 'cmd.exe' AND ps.name IN ('exe') ps.name", err: errors.New("ps.name = 'cmd.exe' AND ps.name IN ('exe') ps.name\n╭──────────────────────────────────────────^\n|\n|\n╰─────────────────── expected operator, ')', ',', '|'")},
		{expr: "ip_cidr(net.dip) = '24'", err: errors.New("ip_cidr function is undefined. Did you mean one of BASE|CIDR_CONTAINS|CONCAT|COUNT|DIR|ENTROPY|EXT|FOREACH|GET_REG_VALUE|GLOB|INDEXOF|IS_ABS|IS_MINIDUMP|LENGTH|LOWER|LTRIM|MD5|REGEX|REPLACE|RTRIM|SPLIT|SUBSTR|UNDEFINED|UPPER|VOLUME|YARA?")},

		{expr: "ps.name = 'cmd.exe' and not cidr_contains(net.sip, '172.14.0.0')"},
		{expr: "ps.name = 'cmd.exe' and ps.exe not imatches '?:\\\\Windows'"},
		{expr: "ps.name not imatches 'cmd.exe' and not (ps.exe imatches '?:\\\\Windows')"},
		{expr: "ps.name not imatches 'cmd.exe' and not ps.exe", err: errors.New("ps.name not imatches 'cmd.exe' and not ps.exe\n╭──────────────────────────────────^\n|\n|\n╰─────────────────── expected boolean field, (")},
		{expr: "ps.name not imatches 'cmd.exe' and not ps.is_protected"},
		{expr: `ps.envs[ProgramFiles] = 'C:\\Program Files'`},
		{expr: `ps.envs imatches 'C:\\Program Files'`},
		{expr: `ps.pid[1] = 'svchost.exe'`, err: errors.New("ps.pid[1] = 'svchost.exe'\n╭──────^\n|\n|\n╰─────────────────── expected field without argument")},
		{expr: `ps.envs[ProgramFiles = 'svchost.exe'`, err: errors.New("ps.envs[ProgramFiles = 'svchost.exe'\n╭───────────────────^\n|\n|\n╰─────────────────── expected ]")},
		{expr: `evt.arg = 'svchost.exe'`, err: errors.New("evt.arg = 'svchost.exe'\n╭──────^\n|\n|\n╰─────────────────── expected field argument")},
		{expr: `evt.arg[name] = 'svchost.exe'`},
		{expr: `evt.arg[Name$] = 'svchost.exe'`, err: errors.New("evt.arg[Name$] = 'svchost.exe'\n╭───────^\n|\n|\n╰─────────────────── expected a valid field argument matching the pattern [a-z0-9_]+")},
		{expr: `ps.ancestor[0] = 'svchost.exe'`},
		{expr: `ps.ancestor[l0l] = 'svchost.exe'`, err: errors.New("ps.ancestor[l0l] = 'svchost.exe'\n╭───────────^\n|\n|\n╰─────────────────── expected a valid field argument matching the pattern [0-9]+")},
	}

	for i, tt := range tests {
		p := NewParser(tt.expr)
		_, err := p.ParseExpr()
		if err == nil && tt.err != nil {
			t.Errorf("%d. exp=%s expected error=%v", i, tt.expr, tt.err)
		} else if err != nil && tt.err != nil {
			assert.EqualError(t, tt.err, err.Error())
		} else if err != nil && tt.err == nil {
			t.Errorf("%d. exp=%s got error=%v", i, tt.expr, err)
		}
	}
}

func TestParseUnaryExpr(t *testing.T) {
	var tests = []struct {
		expr       string
		ee         ast.Expr
		err        string
		assertions func(t *testing.T, e ast.Expr)
	}{
		{"ps.name", &ast.FieldLiteral{}, "", nil},
		{"ps.name[", &ast.FieldLiteral{}, "expected ident, integer", nil},
		{"ps.name[svchost.exe]", &ast.FieldLiteral{}, "expected field without argument", nil},
		{"ps.ancestor[1]", &ast.FieldLiteral{}, "", func(t *testing.T, e ast.Expr) {
			f := e.(*ast.FieldLiteral)
			assert.Equal(t, "1", f.Arg)
		}},
		{"$entry", &ast.BareBoundVariableLiteral{}, "", nil},
		{"$entry.entropy", &ast.BoundSegmentLiteral{}, "", func(t *testing.T, e ast.Expr) {
			s := e.(*ast.BoundSegmentLiteral)
			assert.Equal(t, fields.EntropySegment, s.Segment)
			assert.Equal(t, "$entry.entropy", s.Value)
		}},
		{"$entry.file.path", &ast.BoundFieldLiteral{}, "", func(t *testing.T, e ast.Expr) {
			f := e.(*ast.BoundFieldLiteral)
			assert.Equal(t, fields.FilePath, f.Field.Field)
			assert.Equal(t, "$entry.file.path", f.Value)
		}},
		{"$entry.foo", nil, "expected field/segment after bound ref", nil},
		{"('a', 'b', 'c')", &ast.ListLiteral{}, "", nil},
		{"('a', 'b', 'c'", nil, "expected ')'", nil},
		{"base(file.path)", &ast.Function{}, "", nil},
		{"base(file.path,", &ast.Function{}, "expected field, bound field, string, number, bool, ip, function", nil},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			p := NewParser(tt.expr)

			expr, err := p.parseUnaryExpr()
			if err != nil && tt.err != "" {
				require.ErrorContains(t, err, tt.err)
			}
			if err != nil && tt.err == "" {
				assert.Fail(t, err.Error())
			}

			assert.IsType(t, tt.ee, expr)

			if tt.assertions != nil {
				tt.assertions(t, expr)
			}
		})
	}
}

func TestParseFunction(t *testing.T) {
	var tests = []struct {
		expr string
		err  error
	}{
		{expr: "cidr_contains(net.dip)", err: errors.New("CIDR_CONTAINS function requires 2 argument(s) but 1 argument(s) given")},
		{expr: "cidr_contains(net.dip, 12)", err: errors.New("argument #2 (cidr) in function CIDR_CONTAINS should be one of: string")},
		{expr: "cidr_contains(net.dip, '172.17.12.4/24')"},
		{expr: "cidr_contains($e1.net.dip, '172.17.12.4/24')"},
		{expr: "md('172.17.12.4')", err: errors.New("md function is undefined")},
		{expr: "concat('hello ', 'world')"},
		{expr: "concat('hello')", err: errors.New("CONCAT function requires 2 argument(s) but 1 argument(s) given")},
		{expr: "ltrim('hello world', 'hello ')"},
		{expr: "replace('hello world', 'hello', 'hell', 'world')", err: errors.New("old/new replacements mismatch")},
		{expr: "replace('hello world', 'hello', 'hell', 'world', 'war', 'hello')", err: errors.New("old/new replacements mismatch")},
		{expr: "replace('hello world', 'hello', 'hell', 'world', 'war', 'hello', 'warld', 'old', 'new', 'one')", err: errors.New("old/new replacements mismatch")},
		{expr: "indexof('hello', 'h', 'frst')", err: errors.New("frst is not a valid index search order")},
		{expr: "base('C:\\\\Windows\\\\cmd.exe', false)"},
		{expr: "foreach(ps.modules, $n, $n = 'user32.dll')"},
		{expr: "foreach(ps._ancestors, $proc, $proc.name = 'svchost.exe')"},
		{expr: "foreach(ps._ancestors, $proc, $process.name = 'svchost.exe')", err: errors.New(`undeclared bound variable $process in predicate "$process.name = svchost.exe"`)},
		{expr: "foreach(ps._ancestors, $proc, $proc.pid = 4 or $process.name = 'svchost.exe')", err: errors.New(`undeclared bound variable $process in predicate "$proc.pid = 4 OR $process.name = svchost.exe"`)},
		{expr: "foreach(ps._ancestors, $ps, $ps.name = 'svchost.exe')", err: errors.New(`"$ps" is a reserved bound variable name`)},
		{expr: "foreach(pe._sections, $sec, $sec.protection = 'RWX')", err: errors.New(`unrecognized property "protection" accessing bound variable $sec. Allowed properties [name, size, entropy, md5]`)},
		{expr: "foreach(ps.modules, $n, $n.name = 'user32.dll')", err: errors.New(`unrecognized property "name" accessing bound variable $n. Allowed properties []`)},
		{expr: "foreach(ps._ancestors, $proc, ($proc.name = 'svchost.exe' and $proc.sessionid > 0) or $proc.sid = 'S-1-5-8')"},
		{expr: "foreach(ps._ancestors, $proc, $proc.name = 'svchost.exe' and ps.cwd imatches '?:\\\\Windows\\\\System32\\\\*', ps.cwd)"},
		{expr: "foreach(ps._ancestors, $proc, $proc.name = 'svchost.exe', ps.cwd)", err: errors.New(`one of captured field(s) (ps.cwd) not used in predicate "$proc.name = svchost.exe"`)},
		{expr: "foreach(ps._ancestors, $proc, $proc.name = 'svchost.exe' and ps.cwd != ' ')", err: errors.New(`field ps.cwd used in predicate "$proc.name = svchost.exe AND ps.cwd !=  " but not captured`)},
		{expr: "foreach(ps._ancestors, $proc, $proc.name = 'svchost.exe' and ps.cwd = '.' and ps.sid = 'S-1-5-18', ps.cwd, ps.sid)"},
		{expr: "foreach(ps._ancestors, $proc, $proc.name = 'svchost.exe' and ps.cwd = '.' and ps.sid = 'S-1-5-18', ps.cwd)", err: errors.New(`field ps.sid used in predicate "$proc.name = svchost.exe AND ps.cwd = . AND ps.sid = S-1-5-18" but not captured`)},
	}

	for i, tt := range tests {
		p := NewParser(tt.expr)
		_, err := p.ParseExpr()
		if err == nil && tt.err != nil {
			t.Errorf("%d. exp=%s expected error=%v", i, tt.expr, tt.err)
		} else if err != nil && tt.err != nil {
			assert.True(t, strings.Contains(err.Error(), tt.err.Error()), fmt.Sprintf("exp=%v got=%v", tt.err, err))
		} else if err != nil && tt.err == nil {
			t.Errorf("%d. exp=%s got error=%v", i, tt.expr, err)
		}
	}
}

// testMacros is the macro resolver that knows names, but not bodies.
type testMacros struct {
	exprs map[string]struct{}
	lists map[string]struct{}
}

func newTestMacros(exprs []string, lists []string) testMacros {
	m := testMacros{exprs: make(map[string]struct{}), lists: make(map[string]struct{})}
	for _, e := range exprs {
		m.exprs[e] = struct{}{}
	}
	for _, l := range lists {
		m.lists[l] = struct{}{}
	}
	return m
}

func (m testMacros) IsMacro(name string) bool {
	_, e := m.exprs[name]
	_, l := m.lists[name]
	return e || l
}

func (m testMacros) IsListMacro(name string) bool { _, ok := m.lists[name]; return ok }

func TestParseMacroRefs(t *testing.T) {
	macros := newTestMacros([]string{"spawn_process", "modify"}, []string{"shells"})

	var tests = []struct {
		name     string
		expr     string
		macros   MacroResolver
		expected string
		err      string
	}{
		{
			"expression macro in binary expr",
			"spawn_process and ps.name in ('cmd.exe', 'powershell.exe')",
			macros,
			"spawn_process AND ps.name IN (cmd.exe, powershell.exe)",
			"",
		},
		{
			"list macro as the right operand of in",
			"spawn_process and ps.name in shells",
			macros,
			"spawn_process AND ps.name IN shells",
			"",
		},
		{
			"list macro as the right operand of infix negated in",
			"ps.name not in shells",
			macros,
			"NOT ps.name IN shells",
			"",
		},
		{
			"parenthesized macro",
			"(modify) and file.name = 'a'",
			macros,
			"(modify) AND file.name = a",
			"",
		},
		{
			"negated macro",
			"not spawn_process",
			macros,
			"NOT spawn_process",
			"",
		},
		{
			"macro as the only expression",
			"modify",
			macros,
			"modify",
			"",
		},
		{
			"macro as the function argument",
			"entropy(file.name) > 0.22 and spawn_process",
			macros,
			"entropy(file.name) > 2.2e-01 AND spawn_process",
			"",
		},
		{
			"unknown identifier is a syntax error",
			"spawn_process and ren",
			macros,
			"",
			"expected field, bound field, string, number, bool, ip, function",
		},
		{
			"macros are unknown without resolver",
			"spawn_process and ps.name = 'cmd.exe'",
			nil,
			"",
			"expected field, bound field, string, number, bool, ip, function",
		},
		{
			"in requires list or a list macro",
			"ps.name in spawn_process",
			macros,
			"",
			"expected '('",
		},
		{
			"in requires parenthesis without resolver",
			"ps.name in shells",
			nil,
			"",
			"expected '('",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				expr ast.Expr
				err  error
			)
			if tt.macros == nil {
				expr, err = Parse(tt.expr)
			} else {
				expr, err = Parse(tt.expr, WithMacroResolver(tt.macros))
			}
			if tt.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expected, expr.String())
		})
	}
}

func TestParseMacroRefPosition(t *testing.T) {
	expr, err := Parse("evt.name = 'CreateFile' and spawn_process", WithMacroResolver(newTestMacros([]string{"spawn_process"}, nil)))
	require.NoError(t, err)

	bin, ok := expr.(*ast.BinaryExpr)
	require.True(t, ok)
	ref, ok := bin.RHS.(*ast.MacroRef)
	require.True(t, ok)
	assert.Equal(t, "spawn_process", ref.Name)
	// the position points past the beginning of the expression, where the reference is
	assert.Positive(t, ref.Pos)
}

func TestParseSequence(t *testing.T) {
	var tests = []struct {
		expr          string
		err           error
		maxSpan       time.Duration
		isConstrained bool
	}{
		{
			`evt.name = 'CreateProcess'|
			 |evt.name = 'CreateFile'|
			`,
			errors.New("expected |"),
			time.Duration(0),
			false,
		},
		{
			`|evt.name = 'CreateProcess'
			 evt.name = 'CreateFile'|
			`,
			errors.New("expected operator, ')', ',', '|'"),
			time.Duration(0),
			false,
		},
		{
			`|evt.name = 'CreateProcess'|
			 |evt.name = 'CreateFile'
			`,
			errors.New("expected |"),
			time.Duration(0),
			false,
		},
		{
			`|evt.name = 'CreateProcess'|
			 |evt.name = 'CreateFile'|
			`,
			nil,
			time.Duration(0),
			false,
		},
		{
			`|evt.name = 'CreateProcess'| by ps.exe
			 |evt.name = 'CreateFile'| by file.name
			`,
			nil,
			time.Duration(0),
			true,
		},
		{
			`|evt.name = 'CreateProcess'| by ps.exe, ps.uuid
			 |evt.name = 'CreateFile'| by file.name, ps.uuid
			`,
			nil,
			time.Duration(0),
			true,
		},
		{
			`by ps.exe, ps.uuid
			 |evt.name = 'CreateProcess'|
			 |evt.name = 'CreateFile'|
			`,
			nil,
			time.Duration(0),
			true,
		},
		{
			`|evt.name = 'CreateProcess'| by ps.exe, 
			 |evt.name = 'CreateFile'| by file.name, ps.uuid
			`,
			errors.New("expected field"),
			time.Duration(0),
			true,
		},
		{

			`by ps.pid
			 |evt.name = 'CreateProcess'|
			 |evt.name = 'CreateFile'|
			`,
			nil,
			time.Duration(0),
			true,
		},
		{

			`by ps.pid
			 |evt.name = 'CreateProcess'| by ps.pid
			 |evt.name = 'CreateFile'|
			`,
			errors.New("all steps require the 'by' statement"),
			time.Duration(0),
			true,
		},
		{

			`|evt.name = 'CreateProcess'| by ps.pid
			 |evt.name = 'CreateFile'|
			`,
			errors.New("all steps require the 'by' statement"),
			time.Duration(0),
			true,
		},
		{

			`maxspan 20s
			 |evt.name = 'CreateProcess'| by ps.pid
			 |evt.name = 'CreateFile'| by ps.pid
			`,
			nil,
			time.Second * 20,
			true,
		},
		{

			`maxspan 30s
			 |evt.name = 'CreateProcess'|
			 |evt.name = 'CreateFile'|
			`,
			nil,
			time.Second * 30,
			false,
		},
		{

			`maxspan 30s
			 |evt.name = 'CreateProcess'| as e1
			 |evt.name = 'CreateFile' and $e1.ps.name = file.name |
			`,
			nil,
			time.Second * 30,
			false,
		},
		{

			`maxspan 30s
			 |evt.name = 'CreateProcess'| as e1
			 |evt.name = 'CreateFile' and $e1.ps.ame = file.name |
			`,
			errors.New("expected field/segment after bound ref"),
			time.Second * 30,
			false,
		},
		{

			`maxspan 40h
			 |evt.name = 'CreateProcess'| as e1
			 |evt.name = 'CreateFile' and $e1.ps.ame = file.name |
			`,
			errors.New("maximum span 40h0m0s cannot be greater than 4h"),
			time.Hour * 40,
			false,
		},
		{

			`maxspan 2m
			 by ps.uuid
			 |evt.name = 'CreateProcess'| by ps.uuid
			 |evt.name = 'CreateFile'| by ps.uuid
			`,
			errors.New("sequence mixes global and per-expression 'by' statements"),
			time.Minute * 2,
			true,
		},
	}

	for i, tt := range tests {
		p := NewParser(tt.expr)
		expr, err := p.parseSequenceExpr()
		if err == nil && tt.err != nil {
			t.Errorf("%d. exp=%s expected error=\n%v", i, tt.expr, tt.err)
		} else if err != nil && tt.err == nil {
			t.Errorf("%d. exp=%s got error=\n%v", i, tt.expr, err)
		}

		if err != nil && tt.err != nil {
			assert.True(t, strings.Contains(err.Error(), tt.err.Error()), fmt.Sprintf("error '%v' should contain '%v'", err, tt.err))
		}

		seq, ok := expr.(*ast.SequenceExpr)

		if ok {
			if seq.MaxSpan != tt.maxSpan {
				t.Errorf("%d. exp=%s maxspan=%s got maxspan=%v", i, tt.expr, tt.maxSpan, seq.MaxSpan)
			}
			if seq.IsConstrained() != tt.isConstrained {
				t.Errorf("%d. exp=%s isConstrained=%t got isConstrained=%t", i, tt.expr, tt.isConstrained, seq.IsConstrained())
			}
		}
	}
}
