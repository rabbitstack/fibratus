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
	"bytes"
	"net"
	"strconv"
)

// StringLiteral represents a string literal.
type StringLiteral struct {
	Value string
}

// FieldLiteral represents a field literal.
type FieldLiteral struct {
	Value string
}

// IntegerLiteral represents a signed number literal.
type IntegerLiteral struct {
	Value int64
}

// UnsignedLiteral represents an unsigned number literal.
type UnsignedLiteral struct {
	Value uint64
}

// DecimalLiteral represents an floating point number literal.
type DecimalLiteral struct {
	Value float64
}

// IPLiteral represents an IP literal.
type IPLiteral struct {
	Value net.IP
}

func (i IPLiteral) String() string {
	return i.Value.String()
}

func (i IntegerLiteral) String() string {
	return strconv.Itoa(int(i.Value))
}

func (s StringLiteral) String() string {
	return s.Value
}

func (f FieldLiteral) String() string {
	return f.Value
}

func (u UnsignedLiteral) String() string {
	return strconv.Itoa(int(u.Value))
}

func (d DecimalLiteral) String() string {
	return strconv.FormatFloat(d.Value, 'e', -1, 64)
}

// ListLiteral represents a list of tag key literals.
type ListLiteral struct {
	Values []string
}

// String returns a string representation of the literal.
func (s *ListLiteral) String() string {
	var buf bytes.Buffer
	_, _ = buf.WriteString("(")
	for idx, tagKey := range s.Values {
		if idx != 0 {
			_, _ = buf.WriteString(", ")
		}
		_, _ = buf.WriteString(tagKey)
	}
	_, _ = buf.WriteString(")")
	return buf.String()
}
