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
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"strings"
)

// token represents the lexical token of the filter expression
type token int

const (
	illegal token = iota
	ws
	eof

	field // ps.name
	str   // 'cmd.exe'
	badstr
	badesc
	ident
	dec      // 123.3
	integer  // 123
	duration // 13h
	ip       // 192.168.1.23
	badip    // 192.156.300.12

	opBeg
	and        // and
	or         // or
	not        // not
	in         // in
	contains   // contains
	icontains  // icontains
	startswith // startswith
	endswith   // endswith
	eq         // =
	neq        // !=
	lt         // <
	lte        // <=
	gt         // >
	gte        // >=
	opEnd

	lparen // (
	rparen // )
	comma  // ,
	dot    // .
)

var keywords map[string]token

func init() {
	keywords = make(map[string]token)
	for _, tok := range []token{and, or, contains, icontains, not, in, startswith, endswith} {
		keywords[strings.ToLower(tokens[tok])] = tok
	}
}

var tokens = [...]string{
	illegal: "ILLEGAL",
	eof:     "EOF",
	ws:      "WS",

	ident:    "IDENT",
	field:    "FIELD",
	integer:  "INTEGER",
	dec:      "DECIMAL",
	duration: "DURATION",
	str:      "STRING",
	badstr:   "BADSTRING",
	badesc:   "BADESCAPE",
	ip:       "IPADDRESS",
	badip:    "BADIPADDRESS",

	and:        "AND",
	or:         "OR",
	contains:   "CONTAINS",
	icontains:  "ICONTAINS",
	not:        "NOT",
	in:         "IN",
	startswith: "STARTSWITH",
	endswith:   "ENDSWITH",

	eq:  "=",
	neq: "!=",
	lt:  "<",
	lte: "<=",
	gt:  ">",
	gte: ">=",

	lparen: "(",
	rparen: ")",
	comma:  ",",
	dot:    ".",
}

// isOperator determines whether the current token is an operator.
func (tok token) isOperator() bool { return tok > opBeg && tok < opEnd }

// String returns the string representation of the token.
func (tok token) String() string {
	if tok >= 0 && tok < token(len(tokens)) {
		return tokens[tok]
	}
	return ""
}

// precedence returns the operator precedence of the binary operator token.
func (tok token) precedence() int {
	switch tok {
	case or:
		return 1
	case and:
		return 2
	case eq, neq, lt, lte, gt, gte:
		return 3
	case in, contains, icontains, startswith, endswith:
		return 4
	}
	return 0
}

func tokstr(tok token, lit string) string {
	if lit != "" {
		return lit
	}
	return tok.String()
}

// lookup returns the token associated with a given string.
func lookup(id string) (token, string) {
	if tok, ok := keywords[strings.ToLower(id)]; ok {
		return tok, ""
	}
	if tok := fields.Lookup(id); tok != "" {
		return field, id
	}
	return ident, id
}
