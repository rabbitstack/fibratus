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
	Illegal token = iota
	WS
	EOF

	Field      // ps.name
	BoundField // $evt1.file.name
	Str        // 'cmd.exe'
	Badstr
	Badesc
	Ident
	Decimal  // 123.3
	Integer  // 123
	Duration // 13h
	IP       // 192.168.1.23
	BadIP    // 192.156.300.12
	True     // true
	False    // false

	opBeg
	And         // and
	Or          // or
	In          // in
	IIn         // iin
	Not         // not
	Contains    // contains
	IContains   // icontains
	IStartswith // istartswith
	Startswith  // startswith
	Endswith    // endswith
	IEndswith   // iendswith
	Matches     // matches
	IMatches    // imatches
	Fuzzy       // fuzzy
	IFuzzy      // ifuzzy
	Fuzzynorm   // fuzzynorm
	IFuzzynorm  // ifuzzynorm
	Eq          // =
	IEq         // ~=
	Neq         // !=
	Lt          // <
	Lte         // <=
	Gt          // >
	Gte         // >=
	opEnd

	Lparen // (
	Rparen // )
	Comma  // ,
	Dot    // .
	Pipe   // |

	Seq     // SEQUENCE
	MaxSpan // MAXSPAN
	By      // BY
	As      // AS
)

var keywords map[string]token

func init() {
	keywords = make(map[string]token)
	for _, tok := range []token{And, Or, Contains, IContains, In,
		IIn, Not, Startswith, IStartswith, Endswith, IEndswith,
		Matches, IMatches, Fuzzy, IFuzzy, Fuzzynorm, IFuzzynorm,
		Seq, MaxSpan, By, As} {
		keywords[strings.ToLower(tokens[tok])] = tok
	}
	keywords["true"] = True
	keywords["false"] = False
}

var tokens = [...]string{
	Illegal: "ILLEGAL",
	EOF:     "EOF",
	WS:      "WS",

	Ident:      "IDENT",
	Field:      "FIELD",
	BoundField: "BOUNDFIELD",
	Integer:    "INTEGER",
	Decimal:    "DECIMAL",
	Duration:   "DURATION",
	Str:        "STRING",
	Badstr:     "BADSTRING",
	Badesc:     "BADESCAPE",
	IP:         "IPADDRESS",
	BadIP:      "BADIPADDRESS",
	True:       "TRUE",
	False:      "FALSE",

	And:         "AND",
	Or:          "OR",
	Contains:    "CONTAINS",
	IContains:   "ICONTAINS",
	In:          "IN",
	IIn:         "IIN",
	Not:         "NOT",
	Startswith:  "STARTSWITH",
	IStartswith: "ISTARTSWITH",
	Endswith:    "ENDSWITH",
	IEndswith:   "IENDSWITH",
	Matches:     "MATCHES",
	IMatches:    "IMATCHES",
	Fuzzy:       "FUZZY",
	IFuzzy:      "IFUZZY",
	Fuzzynorm:   "FUZZYNORM",
	IFuzzynorm:  "IFUZZYNORM",

	Eq:  "=",
	IEq: "~=",
	Neq: "!=",
	Lt:  "<",
	Lte: "<=",
	Gt:  ">",
	Gte: ">=",

	Lparen: "(",
	Rparen: ")",
	Comma:  ",",
	Dot:    ".",
	Pipe:   "|",

	Seq:     "SEQUENCE",
	MaxSpan: "MAXSPAN",
	By:      "BY",
	As:      "AS",
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
	case Or:
		return 1
	case And:
		return 2
	case Not:
		return 3
	case Eq, IEq, Neq, Lt, Lte, Gt, Gte:
		return 4
	case In, IIn, Contains, IContains, Startswith, IStartswith, Endswith, IEndswith,
		Matches, IMatches, Fuzzy, IFuzzy, Fuzzynorm, IFuzzynorm:
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

// lookup returns the token associated with a given string.
func lookup(id string) (token, string) {
	if tok, ok := keywords[strings.ToLower(id)]; ok {
		return tok, ""
	}
	if tok := fields.Lookup(id); tok != "" {
		return Field, id
	}
	return Ident, id
}
