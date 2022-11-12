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
	"testing"
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
