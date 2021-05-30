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
	"fmt"
	"strings"
)

// ParseError represents an error that occurred during parsing.
type ParseError struct {
	Expr     string
	Message  string
	Found    string
	Expected []string
	Pos      int
}

// newParseError returns a new instance of ParseError.
func newParseError(found string, expected []string, pos int, expr string) *ParseError {
	return &ParseError{Found: found, Expected: expected, Pos: pos, Expr: expr}
}

// Error returns the string representation of the error.
func (e *ParseError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s at line %d, char %d", e.Message, e.Pos+1, e.Pos+1)
	}
	l := e.Pos + 1
	var sb strings.Builder
	sb.WriteRune('\n')
	sb.WriteString(strings.TrimSpace(e.Expr))
	sb.WriteRune('\n')
	for l > 0 {
		l--
		sb.WriteRune(' ')
		if l == 0 {
			sb.WriteString(fmt.Sprintf("^ expected %s", strings.Join(e.Expected, ", ")))
		}
	}
	return sb.String()
}
