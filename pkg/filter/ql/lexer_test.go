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
	"strings"
	"testing"
)

func TestScanner(t *testing.T) {
	var tests = []struct {
		s   string
		tok token
		lit string
		pos int
	}{
		// special tokens
		{s: ``, tok: eof},
		{s: `#`, tok: illegal, lit: `#`},
		{s: ` `, tok: ws, lit: " "},
		{s: "\t", tok: ws, lit: "\t"},

		// logical operators
		{s: `AND`, tok: and},
		{s: `and`, tok: and},
		{s: `OR`, tok: or},
		{s: `or`, tok: or},

		{s: `=`, tok: eq},
		{s: `<>`, tok: neq},
		{s: `! `, tok: illegal, lit: "!"},
		{s: `<`, tok: lt},
		{s: `<=`, tok: lte},
		{s: `>`, tok: gt},
		{s: `>=`, tok: gte},
		{s: `IN`, tok: in},
		{s: `in`, tok: in},

		// misc tokens
		{s: `(`, tok: lparen},
		{s: `)`, tok: rparen},
		{s: `,`, tok: comma},

		// fields
		{s: `ps.name`, tok: field, lit: "ps.name"},
		{s: `ps.pe.sections[.debug$S].entropy`, tok: field, lit: "ps.pe.sections[.debug$S].entropy"},
		{s: `ps.envs[CommonProgramFiles86]`, tok: field, lit: "ps.envs[CommonProgramFiles86]"},

		// identifiers
		{s: `foo`, tok: ident, lit: `foo`},
		{s: `_foo`, tok: ident, lit: `_foo`},
		{s: `Zx12_3U_-`, tok: ident, lit: `Zx12_3U_`},
		{s: `"foo\"bar\""`, tok: ident, lit: `foo"bar"`},

		// IP address
		{s: "172.17.0.1", tok: ip, lit: "172.17.0.1"},
		{s: "172.17.1", tok: badip, lit: "172.17.1"},
		{s: "172.317.1.2", tok: badip, lit: "172.317.1.2"},
		{s: "172.2.266.2", tok: badip, lit: "172.2.266.2"},

		// strings
		{s: `'testing 123!'`, tok: str, lit: `testing 123!`},
		{s: `'foo\nbar'`, tok: str, lit: "foo\nbar"},
		{s: `'foo\\bar'`, tok: str, lit: "foo\\bar"},

		// numbers
		{s: "6.2323", tok: dec, lit: "6.2323"},
	}

	for i, tt := range tests {
		s := newScanner(strings.NewReader(tt.s))
		tok, pos, lit := s.scan()
		if tt.tok != tok {
			t.Errorf("%d. %q token mismatch: exp=%q got=%q <%q>", i, tt.s, tt.tok, tok, lit)
		} else if tt.pos != pos {
			t.Errorf("%d. %q pos mismatch: exp=%#v got=%#v", i, tt.s, tt.pos, pos)
		} else if tt.lit != lit {
			t.Errorf("%d. %q literal mismatch: exp=%q got=%q", i, tt.s, tt.lit, lit)
		}
	}
}
