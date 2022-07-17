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
	"regexp"
	"strings"
)

// token represents the lexical token of the filter expression
type token int

const (
	illegal token = iota
	ws
	eof

	field          // ps.name
	str            // 'cmd.exe'
	patternBinding // $1.ps.name
	badstr
	badesc
	ident
	dec      // 123.3
	integer  // 123
	duration // 13h
	ip       // 192.168.1.23
	badip    // 192.156.300.12
	truet    // true
	falset   // false

	opBeg
	and         // and
	or          // or
	in          // in
	iin         // iin
	not         // not
	contains    // contains
	icontains   // icontains
	istartswith // istartswith
	startswith  // startswith
	endswith    // endswith
	iendswith   // iendswith
	matches     // matches
	imatches    // imatches
	fuzzy       // fuzzy
	ifuzzy      // ifuzzy
	fuzzynorm   // fuzzynorm
	ifuzzynorm  // ifuzzynorm
	eq          // =
	neq         // !=
	lt          // <
	lte         // <=
	gt          // >
	gte         // >=
	opEnd

	lparen // (
	rparen // )
	comma  // ,
	dot    // .
)

var keywords map[string]token

func init() {
	keywords = make(map[string]token)
	for _, tok := range []token{and, or, contains, icontains, in,
		iin, not, startswith, istartswith, endswith, iendswith,
		matches, imatches, fuzzy, ifuzzy, fuzzynorm, ifuzzynorm} {
		keywords[strings.ToLower(tokens[tok])] = tok
	}
	keywords["true"] = truet
	keywords["false"] = falset
}

var tokens = [...]string{
	illegal: "ILLEGAL",
	eof:     "EOF",
	ws:      "WS",

	ident:          "IDENT",
	field:          "FIELD",
	patternBinding: "PATTERNBINDING",
	integer:        "INTEGER",
	dec:            "DECIMAL",
	duration:       "DURATION",
	str:            "STRING",
	badstr:         "BADSTRING",
	badesc:         "BADESCAPE",
	ip:             "IPADDRESS",
	badip:          "BADIPADDRESS",
	truet:          "TRUE",
	falset:         "FALSE",

	and:         "AND",
	or:          "OR",
	contains:    "CONTAINS",
	icontains:   "ICONTAINS",
	in:          "IN",
	iin:         "IIN",
	not:         "NOT",
	startswith:  "STARTSWITH",
	istartswith: "ISTARTSWITH",
	endswith:    "ENDSWITH",
	iendswith:   "IENDSWITH",
	matches:     "MATCHES",
	imatches:    "IMATCHES",
	fuzzy:       "FUZZY",
	ifuzzy:      "IFUZZY",
	fuzzynorm:   "FUZZYNORM",
	ifuzzynorm:  "IFUZZYNORM",

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
	case not:
		return 3
	case eq, neq, lt, lte, gt, gte:
		return 4
	case in, iin, contains, icontains, startswith, istartswith, endswith, iendswith,
		matches, imatches, fuzzy, ifuzzy, fuzzynorm, ifuzzynorm:
		return 5
	}
	return 0
}

func tokstr(tok token, lit string) string {
	if lit != "" {
		return lit
	}
	return tok.String()
}

var patternBindingRegexp = regexp.MustCompile("\\$[1-9]\\.(.+)")

// lookup returns the token associated with a given string.
func lookup(id string) (token, string) {
	if tok, ok := keywords[strings.ToLower(id)]; ok {
		return tok, ""
	}
	matches := patternBindingRegexp.FindStringSubmatch(id)
	if len(matches) > 0 {
		if tok := fields.Lookup(matches[1]); tok != "" {
			return patternBinding, id
		}
	}
	if tok := fields.Lookup(id); tok != "" {
		return field, id
	}
	return ident, id
}
