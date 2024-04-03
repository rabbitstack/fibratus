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

package ql

import (
	"errors"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestParser(t *testing.T) {
	var tests = []struct {
		expr string
		err  error
	}{
		{expr: "ps.name = 'cmd.exe'"},
		{expr: "ps.name != 'cmd.exe'"},
		{expr: "ps.name <> 'cmd.exe'"},
		{expr: "ps.name <> 'cmd.exe", err: errors.New("ps.name <> 'cmd.exe\n" +
			"           ^ expected field, string, number, bool, ip")},
		{expr: "ps.name = 123"},
		{expr: "net.dip = 172.17.0.9"},
		{expr: "net.dip = 172.17.0.9 and net.dip in ('172.15.9.2')"},
		{expr: "net.dip = 172.17.0.9 and (net.dip not in ('172.15.9.2'))"},

		{expr: "net.dip = 172.17.0", err: errors.New("net.dip = 172.17.0\n" +
			"           ^ expected a valid IP address")},

		{expr: "ps.name = 'cmd.exe' OR ps.name contains 'svc'"},
		{expr: "ps.name = 'cmd.exe' AND (ps.name contains 'svc' OR ps.name != 'lsass')"},
		{expr: "ps.name = 'cmd.exe' AND (ps.name contains 'svc' OR ps.name != 'lsass'", err: errors.New("ps.name = 'cmd.exe' AND (ps.name contains 'svc' OR ps.name != 'lsass'" +
			"^ expected")},

		{expr: "ps.name = 'cmd.exe' OR ((ps.name contains 'svc' AND ps.name != 'lsass') AND ps.ppid != 1)"},

		{expr: "ps.name = 'cmd.exe' OR ((ps.name contains 'svc' AND ps.name != 'lsass' AND ps.ppid != 1)", err: errors.New("ps.name = 'cmd.exe' OR ((ps.name contains 'svc' AND ps.name != 'lsass' AND ps.ppid != 1)" +
			"	^ expected )")},

		{expr: "ps.name = 'cmd.exe' OR ((ps.name contains 'svc' AND ps.name != 'lsass') AND ps.ppid != 1", err: errors.New("ps.name = 'cmd.exe' OR ((ps.name contains 'svc' AND ps.name != 'lsass') AND ps.ppid != 1" +
			"	^ expected )")},

		{expr: "ps.none = 'cmd.exe'", err: errors.New("ps.none = 'cmd.exe'" +
			"	^ expected field, string, number, bool, ip")},

		{expr: "ps.name = 'cmd.exe' AND ps.name IN ('exe') ps.name", err: errors.New("ps.name = 'cmd.exe' AND ps.name IN ('exe') ps.name" +
			"	^ expected operator")},
		{expr: "ip_cidr(net.dip) = '24'", err: errors.New("ip_cidr function is undefined. Did you mean one of CIDR_CONTAINS|MD5?")},

		{expr: "ps.name = 'cmd.exe' and not cidr_contains(net.sip, '172.14.0.0')"},
	}

	for i, tt := range tests {
		p := NewParser(tt.expr)
		_, err := p.ParseExpr()
		if err == nil && tt.err != nil {
			t.Errorf("%d. exp=%s expected error=%v", i, tt.expr, tt.err)
		} else if err != nil && tt.err == nil {
			t.Errorf("%d. exp=%s got error=%v", i, tt.expr, err)
		}
	}
}

func TestExpandMacros(t *testing.T) {
	var tests = []struct {
		c            *config.Filters
		expr         string
		expectedExpr string
		err          error
	}{
		{
			config.FiltersWithMacros(map[string]*config.Macro{"spawn_process": {Expr: "kevt.name = 'CreateProcess'"}}),
			"spawn_process and ps.name in ('cmd.exe', 'powershell.exe')",
			"kevt.name = CreateProcess AND ps.name IN (cmd.exe, powershell.exe)",
			nil,
		},
		{
			config.FiltersWithMacros(map[string]*config.Macro{"span_process": {Expr: "kevt.name = 'CreateProcess'"}}),
			"spawn_process and ps.name in ('cmd.exe', 'powershell.exe')",
			"",
			errors.New("expected field, string, number, bool, ip, function, pattern binding"),
		},
		{
			config.FiltersWithMacros(map[string]*config.Macro{"spawn_process": {Expr: "kevt.name = 'CreateProcess'"}, "command_clients": {List: []string{"cmd.exe", "pwsh.exe"}}}),
			"spawn_process and ps.name in command_clients",
			"kevt.name = CreateProcess AND ps.name IN (cmd.exe, pwsh.exe)",
			nil,
		},
		{
			config.FiltersWithMacros(map[string]*config.Macro{"spawn_process": {Expr: "kevt.nnname = 'CreateProcess'"}, "command_clients": {List: []string{"cmd.exe", "pwsh.exe"}}}),
			"spawn_process and ps.name in command_clients",
			"",
			errors.New("syntax error in \"spawn_process\" macro. expected field, string, number, bool, ip, function, pattern binding"),
		},
		{
			config.FiltersWithMacros(map[string]*config.Macro{
				"rename":    {Expr: "kevt.name = 'RenameFile'"},
				"remove":    {Expr: "kevt.name = 'DeleteFile'"},
				"modify":    {Expr: "rename or remove"},
				"wcm_files": {List: []string{"?:\\Users\\*\\AppData\\*\\Microsoft\\Credentials\\*"}}}),
			"(modify) and file.name imatches wcm_files",
			"(kevt.name = RenameFile OR kevt.name = DeleteFile) AND file.name IMATCHES (?:\\Users\\*\\AppData\\*\\Microsoft\\Credentials\\*)",
			nil,
		},
		{
			config.FiltersWithMacros(map[string]*config.Macro{
				"rename": {Expr: "kevt.name = 'RenameFile'"},
				"remove": {Expr: "kevt.name = 'DeleteFile'"},
				"modify": {Expr: "rename or remove"}}),
			"entropy(file.name) > 0.22 and ren",
			"",
			errors.New("expected field, string, number, bool, ip, function, pattern binding"),
		},
		{
			config.FiltersWithMacros(map[string]*config.Macro{
				"rename": {Expr: "kevt.name = 'RenameFile'"},
				"remove": {Expr: "kevt.name = 'DeleteFile'"},
				"modify": {Expr: "rename or remove"}}),
			"entropy(file.name) > 0.22 and rename",
			"entropy(file.name) > 2.2e-01 AND kevt.name = RenameFile",
			nil,
		},
		{
			config.FiltersWithMacros(map[string]*config.Macro{
				"rename":    {Expr: "kevt.name = 'RenameFile'"},
				"remove":    {Expr: "kevt.name = 'DeleteFile'"},
				"create":    {Expr: "kevt.name = 'CreateFile' and file.operation = 'create'"},
				"modify":    {Expr: "rename or remove"},
				"change_fs": {Expr: "modify or (create)"}}),
			"change_fs",
			"kevt.name = RenameFile OR kevt.name = DeleteFile OR (kevt.name = CreateFile AND file.operation = create)",
			nil,
		},
	}

	for i, tt := range tests {
		p := NewParserWithConfig(tt.expr, tt.c)
		expr, err := p.ParseExpr()
		if err == nil && tt.err != nil {
			t.Errorf("%d. exp=%s expected error=\n%v", i, tt.expr, tt.err)
		} else if err != nil && tt.err == nil {
			t.Errorf("%d. exp=%s got error=\n%v", i, tt.expr, err)
		}
		if tt.expectedExpr != "" && expr.String() != tt.expectedExpr {
			t.Errorf("%d. exp=%s expected expr=%v", i, expr.String(), tt.expectedExpr)
		}
	}
}

func TestParseSequence(t *testing.T) {
	var tests = []struct {
		expr          string
		err           error
		maxSpan       time.Duration
		isConstrained bool
	}{
		{
			`kevt.name = 'CreateProcess'|
			 |kevt.name = 'CreateFile'|
			`,
			errors.New("expected |"),
			time.Duration(0),
			false,
		},
		{
			`|kevt.name = 'CreateProcess'
			 kevt.name = 'CreateFile'|
			`,
			errors.New("expected operator, ')', ',', '|'"),
			time.Duration(0),
			false,
		},
		{
			`|kevt.name = 'CreateProcess'|
			 |kevt.name = 'CreateFile'
			`,
			errors.New("expected |"),
			time.Duration(0),
			false,
		},
		{
			`|kevt.name = 'CreateProcess'|
			 |kevt.name = 'CreateFile'|
			`,
			nil,
			time.Duration(0),
			false,
		},
		{
			`|kevt.name = 'CreateProcess'| by ps.exe
			 |kevt.name = 'CreateFile'| by file.name
			`,
			nil,
			time.Duration(0),
			true,
		},
		{

			`by ps.pid
			 |kevt.name = 'CreateProcess'|
			 |kevt.name = 'CreateFile'|
			`,
			nil,
			time.Duration(0),
			true,
		},
		{

			`by ps.pid
			 |kevt.name = 'CreateProcess'| by ps.pid
			 |kevt.name = 'CreateFile'|
			`,
			errors.New("all expressions require the 'by' statement"),
			time.Duration(0),
			false,
		},
		{

			`|kevt.name = 'CreateProcess'| by ps.pid
			 |kevt.name = 'CreateFile'|
			`,
			errors.New("all expressions require the 'by' statement"),
			time.Duration(0),
			true,
		},
		{

			`maxspan 20s
			 |kevt.name = 'CreateProcess'| by ps.pid
			 |kevt.name = 'CreateFile'| by ps.pid
			`,
			nil,
			time.Second * 20,
			true,
		},
		{

			`maxspan 30s
			 |kevt.name = 'CreateProcess'|
			 |kevt.name = 'CreateFile'|
			`,
			nil,
			time.Second * 30,
			false,
		},
		{

			`maxspan 30s
			 |kevt.name = 'CreateProcess'| as e1
			 |kevt.name = 'CreateFile' and $e1.ps.name = file.name |
			`,
			nil,
			time.Second * 30,
			false,
		},
		{

			`maxspan 30s
			 |kevt.name = 'CreateProcess'| as e1
			 |kevt.name = 'CreateFile' and $e1.ps.ame = file.name |
			`,
			errors.New("expected field after bound ref"),
			time.Second * 30,
			false,
		},
		{

			`maxspan 40h
			 |kevt.name = 'CreateProcess'| as e1
			 |kevt.name = 'CreateFile' and $e1.ps.ame = file.name |
			`,
			errors.New("maximum span 40h0m0s cannot be greater than 4h"),
			time.Hour * 40,
			false,
		},
		{

			`by ps.uuid
			 maxspan 2m
			 |kevt.name = 'CreateProcess'| by ps.child.uuid
			 |kevt.name = 'CreateFile'| by ps.uuid
			`,
			errors.New("sequence mixes global and per-expression 'by' statements"),
			time.Minute * 2,
			true,
		},
	}

	for i, tt := range tests {
		p := NewParser(tt.expr)
		seq, err := p.ParseSequence()
		if err == nil && tt.err != nil {
			t.Errorf("%d. exp=%s expected error=\n%v", i, tt.expr, tt.err)
		} else if err != nil && tt.err == nil {
			t.Errorf("%d. exp=%s got error=\n%v", i, tt.expr, err)
		}

		if seq != nil {
			if seq.MaxSpan != tt.maxSpan {
				t.Errorf("%d. exp=%s maxspan=%s got maxspan=%v", i, tt.expr, tt.maxSpan, seq.MaxSpan)
			}
			if seq.IsConstrained() != tt.isConstrained {
				t.Errorf("%d. exp=%s isConstrained=%t got isConstrained=%t", i, tt.expr, tt.isConstrained, seq.IsConstrained())
			}
		}
	}
}

func TestIsSequenceUnordered(t *testing.T) {
	var tests = []struct {
		expr        string
		isUnordered bool
	}{
		{
			`|kevt.name = 'CreateProcess'| by ps.uuid
			 |kevt.name = 'OpenProcess'| by ps.uuid
			`,
			true,
		},
		{
			`|kevt.name = 'CreateProcess'|
			 |kevt.name = 'CreateFile'|
			`,
			false,
		},
		{
			`|kevt.name = 'CreateProcess'|
			 |kevt.name = 'UnmapViewFile'|
 			 |kevt.name = 'LoadImage'|
			`,
			false,
		},
		{
			`|kevt.name = 'CreateProcess'|
			 |kevt.name = 'SetThreadContext'|
			`,
			true,
		},
		{
			`|kevt.name = 'OpenThread'| by ps.uuid
			 |kevt.name = 'OpenProcess'| by ps.uuid
			`,
			false,
		},
		{
			`|kevt.name = 'OpenThread' or kevt.name = 'OpenProcess'| by ps.uuid
			 |kevt.name = 'SetThreadContext'| by ps.uuid
			`,
			false,
		},
		{
			`|kevt.name = 'RegSetValue'| by ps.uuid
			 |kevt.name = 'SetThreadContext'| by ps.uuid
			`,
			true,
		},
		{
			`|kevt.name = 'RegSetValue'| by ps.uuid
			 |kevt.name = 'RegDeleteValue'| by ps.uuid
			`,
			false,
		},
	}

	for i, tt := range tests {
		p := NewParser(tt.expr)
		seq, err := p.ParseSequence()
		require.NoError(t, err)

		if seq.IsUnordered != tt.isUnordered {
			t.Errorf("%d. exp=%s isUnordered=%t got isUnordered=%t", i, tt.expr, tt.isUnordered, seq.IsUnordered)
		}
	}
}
