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

package ql

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
