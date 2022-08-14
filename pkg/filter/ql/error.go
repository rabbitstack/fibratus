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

// findPosInLine returns the parser position and the line number
// where the syntax error occurred when the expression is split
// over multiple lines.
func findPosInLine(expr string, pos int) (int, int) {
	ln := 1
	for i, c := range []rune(expr) {
		if c == '\n' {
			ln++
		}
		if i == pos {
			switch {
			case ln > 1:
				// multiline expression. Calculate
				// the position relative to the line
				// number by looking back for the
				// previous newline terminator
				j := pos
				for expr[j] != '\n' {
					j--
					// no newline found
					if j == -1 {
						break
					}
				}
				return pos - j + 2, ln
			default:
				// single line expression
				return pos + 1, 1
			}
		}
	}
	return pos + 1, 1
}

type renderer struct {
	strings.Builder
}

func (r *renderer) renderTopGutter()                 { r.WriteString("\n╭") }
func (r *renderer) renderCaret()                     { r.WriteString("^\n|") }
func (r *renderer) renderLeftBorder()                { r.WriteString("|\n") }
func (r *renderer) renderLineWithBorder(line string) { r.WriteString("|" + line) }
func (r *renderer) renderLine(line string)           { r.WriteString(line) }
func (r *renderer) renderNewLine()                   { r.WriteString("\n") }
func (r *renderer) renderLabel(width int, msg string) {
	r.WriteString("╰")
	for i := 0; i <= width; i++ {
		r.WriteString("─")
	}
	r.WriteString(" expected " + msg)

}

func (r *renderer) renderTopBorder(width int) {
	for i := 0; i < width; i++ {
		r.WriteString("─")
	}
}

func render(e *ParseError) string {
	pos, ln := findPosInLine(e.Expr, e.Pos)
	r := renderer{}

	lines := strings.Split(e.Expr, "\n")

	for n, line := range lines {
		if n >= ln {
			r.renderLineWithBorder(line)
		} else {
			r.renderLine(line)
		}
		// insert a new line and start drawing
		// the snippet lines, gutters and borders
		if n == ln-1 {
			r.renderTopGutter()
			r.renderTopBorder(pos - 1)
			r.renderCaret()
		}
		r.renderNewLine()
	}

	r.renderLeftBorder()
	r.renderLabel(18, strings.Join(e.Expected, ", "))

	return r.String()
}

// Error returns the string representation of the error.
func (e *ParseError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s at line %d, char %d", e.Message, e.Pos+1, e.Pos+1)
	}
	return render(e)
}
