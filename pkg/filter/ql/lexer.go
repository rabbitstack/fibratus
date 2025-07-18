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
 *
 *  Copyright (c) 2013-2016 Errplane Inc.
 */

package ql

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
)

// scanner is responsible for splitting up the filter expression into individual tokens. This code is mostly borrowed
// from the influxql repository (https://github.com/influxdata/influxql) with some changes to support the lexing
// of additional tokens such as IP addresses.
type scanner struct {
	r *reader
}

func newScanner(r io.Reader) *scanner {
	return &scanner{r: &reader{r: bufio.NewReader(r)}}
}

// scan returns the next token and position from the underlying reader.
// Also returns the literal text read for strings, numbers, and duration tokens
// since these token types can have different literal representations.
func (s *scanner) scan() (tok token, pos int, lit string) {
	// Read next code point.
	ch0, pos := s.r.read()

	// if we see whitespace then consume all contiguous whitespace.
	// if we see a letter, or certain acceptable special characters, then consume
	// as an ident or reserved word.
	if isWhitespace(ch0) {
		return s.scanWhitespace()
	} else if isLetter(ch0) || ch0 == '_' {
		s.r.unread()
		return s.scanIdent()
	} else if isDigit(ch0) {
		return s.scanNumber()
	}

	// Otherwise, parse individual characters.
	switch ch0 {
	case eof:
		return EOF, pos, ""
	case '"':
		s.r.unread()
		return s.scanIdent()
	case '\'':
		return s.scanString()
	case '.':
		ch1, _ := s.r.read()
		s.r.unread()
		if isDigit(ch1) {
			return s.scanNumber()
		}
		return Dot, pos, ""
	case '=':
		return Eq, pos, ""
	case '~':
		if ch1, _ := s.r.read(); ch1 == '=' {
			return IEq, pos, ""
		}
		s.r.unread()
	case '!':
		if ch1, _ := s.r.read(); ch1 == '=' {
			return Neq, pos, ""
		}
		s.r.unread()
	case '>':
		if ch1, _ := s.r.read(); ch1 == '=' {
			return Gte, pos, ""
		}
		s.r.unread()
		return Gt, pos, ""
	case '<':
		if ch1, _ := s.r.read(); ch1 == '=' {
			return Lte, pos, ""
		} else if ch1 == '>' {
			return Neq, pos, ""
		}
		s.r.unread()
		return Lt, pos, ""
	case '(':
		return Lparen, pos, ""
	case ')':
		return Rparen, pos, ""
	case '|':
		return Pipe, pos, ""
	case ',':
		return Comma, pos, ""
	case '[':
		return LBracket, pos, ""
	case ']':
		return RBracket, pos, ""
	case '$':
		tok, _, lit = s.scanIdent()
		if tok != Ident {
			return tok, pos, "$" + lit
		}
		return BoundVar, pos, "$" + lit
	}
	return Illegal, pos, string(ch0)
}

// scanWhitespace consumes the current rune and all contiguous whitespace.
func (s *scanner) scanWhitespace() (tok token, pos int, lit string) {
	// Create a buffer and read the current character into it.
	var buf bytes.Buffer
	ch, pos := s.r.curr()
	_, _ = buf.WriteRune(ch)

	// Read every subsequent whitespace character into the buffer.
	// Non-whitespace characters and EOF will cause the loop to exit.
	for {
		ch, _ = s.r.read()
		if ch == eof {
			break
		} else if !isWhitespace(ch) {
			s.r.unread()
			break
		} else {
			_, _ = buf.WriteRune(ch)
		}
	}

	return WS, pos, buf.String()
}

func (s *scanner) scanIdent() (tok token, pos int, lit string) {
	// Save the starting position of the identifier.
	_, pos = s.r.read()
	s.r.unread()

	var buf bytes.Buffer
	for {
		if ch, _ := s.r.read(); ch == eof {
			break
		} else if ch == '"' {
			tok0, pos0, lit0 := s.scanString()
			if tok0 == Badstr || tok0 == Badesc {
				return tok0, pos0, lit0
			}
			return Ident, pos, lit0
		} else if isIdentChar(ch) {
			s.r.unread()
			buf.WriteString(scanBareIdent(s.r))
		} else {
			s.r.unread()
			break
		}
	}
	lit = buf.String()

	if tok, lit = lookup(lit); tok != Ident {
		return tok, pos, lit
	}

	return Ident, pos, lit
}

// scanNumber consumes anything that looks like the start of a number.
func (s *scanner) scanNumber() (tok token, pos int, lit string) {
	var buf bytes.Buffer

	// Check if the initial rune is a ".".
	ch, pos := s.r.curr()
	if ch == '.' {
		// Peek and see if the next rune is a digit.
		ch1, _ := s.r.read()
		s.r.unread()
		if !isDigit(ch1) {
			return Illegal, pos, "."
		}
		// Unread the full stop so we can read it later.
		s.r.unread()
	} else {
		s.r.unread()
	}

	// Read as many digits as possible.
	_, _ = buf.WriteString(s.scanDigits())

	// If next code points are a full stop and digit then consume them.
	isDecimal := false
	if ch0, _ := s.r.read(); ch0 == '.' {
		isDecimal = true
		if ch1, _ := s.r.read(); isDigit(ch1) {
			_, _ = buf.WriteRune(ch0)
			_, _ = buf.WriteRune(ch1)
			_, _ = buf.WriteString(s.scanDigits())
		} else {
			s.r.unread()
		}
	} else {
		s.r.unread()
	}

	// Check if next token is a "." and has at least 2 more subsequent "." runes
	// to confirm we have an IP address string
	ch, _ = s.r.read()
	if ch == '.' {
		buf.WriteRune(ch)
		nbDots := 2
		for {
			buf.WriteString(s.scanDigits())
			ch, _ := s.r.read()
			if ch != '.' {
				s.r.unread()
				break
			}
			nbDots++
			_, _ = buf.WriteRune(ch)
		}
		if nbDots != 3 {
			s.r.unread()
			return BadIP, pos, buf.String()
		}
		octets := strings.Split(buf.String(), ".")
		if len(octets) != 4 {
			return BadIP, pos, buf.String()
		}
		// check the range of each octet
		for _, oct := range octets {
			n, err := strconv.Atoi(oct)
			if err != nil {
				return BadIP, pos, buf.String()
			}
			if n < 0 || n > 255 {
				return BadIP, pos, buf.String()
			}
		}
		return IP, pos, buf.String()
	}
	// unread the previously read char
	s.r.unread()

	// Read as a duration or integer if it doesn't have a fractional part.
	if !isDecimal {
		// If the next rune is a letter then this is a duration token.
		if ch0, _ := s.r.read(); isLetter(ch0) || ch0 == 'µ' {
			_, _ = buf.WriteRune(ch0)
			for {
				ch1, _ := s.r.read()
				if !isLetter(ch1) && ch1 != 'µ' {
					s.r.unread()
					break
				}
				_, _ = buf.WriteRune(ch1)
			}

			// Continue reading digits and letters as part of this token.
			for {
				if ch0, _ := s.r.read(); isLetter(ch0) || ch0 == 'µ' || isDigit(ch0) {
					_, _ = buf.WriteRune(ch0)
				} else {
					s.r.unread()
					break
				}
			}
			return Duration, pos, buf.String()
		}
		s.r.unread()
		return Integer, pos, buf.String()
	}

	return Decimal, pos, buf.String()
}

// scanDigits consumes a contiguous series of digits.
func (s *scanner) scanDigits() string {
	var buf bytes.Buffer
	for {
		ch, _ := s.r.read()
		if !isDigit(ch) {
			s.r.unread()
			break
		}
		_, _ = buf.WriteRune(ch)
	}
	return buf.String()
}

// scanBareIdent reads bare identifier from a rune reader.
func scanBareIdent(r io.RuneScanner) string {
	// Read every ident character into the buffer.
	// Non-ident characters and EOF will cause the loop to exit.
	var buf bytes.Buffer
	for {
		ch, _, err := r.ReadRune()
		if err != nil {
			break
		} else if !isIdentChar(ch) {
			_ = r.UnreadRune()
			break
		} else {
			_, _ = buf.WriteRune(ch)
		}
	}
	return buf.String()
}

// scanString consumes a contiguous string of non-quote characters.
// Quote characters can be consumed if they're first escaped with a backslash.
func (s *scanner) scanString() (tok token, pos int, lit string) {
	s.r.unread()
	_, pos = s.r.curr()

	lit, err := ScanString(s.r)
	switch err {
	case errBadString:
		return Badstr, pos, lit
	case errBadEscape:
		_, pos = s.r.curr()
		return Badstr, pos, lit
	default:
		return Str, pos, lit
	}
}

var errBadString = errors.New("bad string")
var errBadEscape = errors.New("bad escape")

// ScanString reads a quoted string from a rune reader.
func ScanString(r io.RuneScanner) (string, error) {
	ending, _, err := r.ReadRune()
	if err != nil {
		return "", errBadString
	}

	var buf bytes.Buffer
	for {
		ch0, _, err := r.ReadRune()
		if ch0 == ending {
			return buf.String(), nil
		} else if err != nil || ch0 == '\n' {
			return buf.String(), errBadString
		} else if ch0 == '\\' {
			// If the next character is an escape then write the escaped char.
			// If it's not a valid escape then return an error.
			ch1, _, _ := r.ReadRune()
			switch ch1 {
			case 'n':
				_, _ = buf.WriteRune('\n')
			case '\\':
				_, _ = buf.WriteRune('\\')
			case '"':
				_, _ = buf.WriteRune('"')
			case '\'':
				_, _ = buf.WriteRune('\'')
			default:
				return string(ch0) + string(ch1), errBadEscape
			}
		} else {
			_, _ = buf.WriteRune(ch0)
		}
	}
}

// bufScanner represents a wrapper for scanner to add a buffer.
// It provides a fixed-length circular buffer that can be unread.
type bufScanner struct {
	s   *scanner
	i   int // buffer index
	n   int // buffer size
	buf [3]struct {
		tok token
		pos int
		lit string
	}
}

// newBufScanner returns a new buffered scanner for a reader.
func newBufScanner(r io.Reader) *bufScanner {
	return &bufScanner{s: newScanner(r)}
}

// scan reads the next token from the scanner.
func (s *bufScanner) scan() (tok token, pos int, lit string) {
	return s.scanFunc(s.s.scan)
}

// scanFunc uses the provided function to scan the next token.
func (s *bufScanner) scanFunc(scan func() (token, int, string)) (tok token, pos int, lit string) {
	// If we have unread tokens then read them off the buffer first.
	if s.n > 0 {
		s.n--
		return s.curr()
	}

	// Move buffer position forward and save the token.
	s.i = (s.i + 1) % len(s.buf)
	buf := &s.buf[s.i]
	buf.tok, buf.pos, buf.lit = scan()

	return s.curr()
}

// unscan pushes the previously token back onto the buffer.
func (s *bufScanner) unscan() { s.n++ }

// curr returns the last read token.
func (s *bufScanner) curr() (tok token, pos int, lit string) {
	buf := &s.buf[(s.i-s.n+len(s.buf))%len(s.buf)]
	return buf.tok, buf.pos, buf.lit
}

type reader struct {
	r   io.RuneScanner
	i   int
	n   int // buffer char count
	pos int // last read rune position
	buf [3]struct {
		ch  rune
		pos int
	}
	eof bool
}

// ReadRune reads the next rune from the reader.
// This is a wrapper function to implement the io.RuneReader interface.
// Note that this function does not return size.
func (r *reader) ReadRune() (ch rune, size int, err error) {
	ch, _ = r.read()
	if ch == eof {
		err = io.EOF
	}
	return
}

// UnreadRune pushes the previously read rune back onto the buffer.
// This is a wrapper function to implement the io.RuneScanner interface.
func (r *reader) UnreadRune() error {
	r.unread()
	return nil
}

var eof = rune(0)

// read reads the next rune from the reader.
func (r *reader) read() (ch rune, pos int) {
	// if we have unread characters then read them off the buffer first.
	if r.n > 0 {
		r.n--
		return r.curr()
	}

	// Read next rune from underlying reader.
	// Any error (including io.EOF) should return as EOF.
	ch, _, err := r.r.ReadRune()
	if err != nil {
		ch = eof
	} else if ch == '\r' {
		if ch, _, err := r.r.ReadRune(); err != nil {
			// nop
		} else if ch != '\n' {
			_ = r.r.UnreadRune()
		}
		ch = '\n'
	}

	// Save character and position to the buffer.
	r.i = (r.i + 1) % len(r.buf)
	buf := &r.buf[r.i]
	buf.ch, buf.pos = ch, r.pos

	// Update position.
	if !r.eof {
		r.pos++
	}

	// Mark the reader as EOF.
	// This is used to avoid doubling the count of EOF characters.
	if ch == eof {
		r.eof = true
	}

	return r.curr()
}

// unread pushes the previously read rune back onto the buffer.
func (r *reader) unread() { r.n++ }

// curr returns the last read character and position.
func (r *reader) curr() (ch rune, pos int) {
	i := (r.i - r.n + len(r.buf)) % len(r.buf)
	buf := &r.buf[i]
	return buf.ch, buf.pos
}

// isWhitespace returns true if the rune is a space, tab, or newline.
func isWhitespace(ch rune) bool { return ch == ' ' || ch == '\t' || ch == '\n' }

// isLetter returns true if the rune is a letter.
func isLetter(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
}

// isDigit returns true if the rune is a digit.
func isDigit(ch rune) bool { return ch >= '0' && ch <= '9' }

// isIdentChar returns true if the rune can be used in an unquoted identifier. $ rune is for special PE section names (e.g. .debug$ | .tls$)
func isIdentChar(ch rune) bool {
	return isLetter(ch) || isDigit(ch) || ch == '_' || ch == '.' || ch == '$'
}
