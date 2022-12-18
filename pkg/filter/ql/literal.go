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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/util/hashers"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/filter/ql/functions"
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

// BoolLiteral represents the logical true/false literal.
type BoolLiteral struct {
	Value bool
}

// IPLiteral represents an IP literal.
type IPLiteral struct {
	Value net.IP
}

type BoundFieldLiteral struct {
	Value string
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

func (b BoolLiteral) String() string {
	return strconv.FormatBool(b.Value)
}

func (b BoundFieldLiteral) String() string {
	return b.Value
}

func (b BoundFieldLiteral) Field() fields.Field {
	n := strings.Index(b.Value, ".")
	if n > 0 {
		return fields.Field(b.Value[n+1:])
	}
	return fields.Field(b.Value)
}

func (b BoundFieldLiteral) Alias() string {
	n := strings.Index(b.Value, ".")
	if n > 0 {
		return b.Value[1:n]
	}
	return b.Value
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

// Function represents a function call.
type Function struct {
	Name string
	Args []Expr
}

// ArgsSlice returns arguments as a slice of strings.
func (f *Function) ArgsSlice() []string {
	args := make([]string, 0, len(f.Args))
	for _, arg := range f.Args {
		args = append(args, arg.String())
	}
	return args
}

// String returns a string representation of the call.
func (f *Function) String() string {
	// join arguments.
	var str []string
	for _, arg := range f.Args {
		str = append(str, arg.String())
	}

	// Write function name and args.
	return fmt.Sprintf("%s(%s)", f.Name, strings.Join(str, ", "))
}

// validate ensures that the function name obtained
// from the parser exists within the internal functions
// catalog. It also validates the function signature to
// make sure required arguments are supplied. Finally, it
// checks the type of each argument with the expected one.
func (f *Function) validate() error {
	fn, ok := funcs[strings.ToUpper(f.Name)]
	if !ok {
		return ErrUndefinedFunction(f.Name)
	}

	if len(f.Args) < fn.Desc().RequiredArgs() ||
		len(f.Args) > len(fn.Desc().Args) {
		return ErrFunctionSignature(fn.Desc(), len(f.Args))
	}

	validationFunc := fn.Desc().ArgsValidationFunc
	if validationFunc != nil {
		if err := validationFunc(f.ArgsSlice()); err != nil {
			return err
		}
	}

	for i, expr := range f.Args {
		arg := fn.Desc().Args[i]
		typ := functions.Unknown
		switch reflect.TypeOf(expr) {
		case reflect.TypeOf(&FieldLiteral{}), reflect.TypeOf(&BoundFieldLiteral{}):
			typ = functions.Field
		case reflect.TypeOf(&IPLiteral{}):
			typ = functions.IP
		case reflect.TypeOf(&StringLiteral{}):
			typ = functions.String
		case reflect.TypeOf(&IntegerLiteral{}):
			typ = functions.Number
		case reflect.TypeOf(&Function{}):
			typ = functions.Func
		case reflect.TypeOf(&ListLiteral{}):
			typ = functions.Slice
		}
		if !arg.ContainsType(typ) {
			return ErrArgumentTypeMismatch(i, arg.Keyword, fn.Name(), arg.Types)
		}
	}
	return nil
}

// SequenceExpr represents a single binary expression within the sequence.
type SequenceExpr struct {
	Expr        Expr
	By          fields.Field
	BoundFields []*BoundFieldLiteral
	Alias       string

	buckets map[uint32]bool
}

func (e *SequenceExpr) init() {
	e.buckets = make(map[uint32]bool)
	e.BoundFields = make([]*BoundFieldLiteral, 0)
}

func (e *SequenceExpr) walk() {
	stringFields := make(map[fields.Field][]string)
	walk := func(n Node) {
		if expr, ok := n.(*BinaryExpr); ok {
			switch lhs := expr.LHS.(type) {
			case *BoundFieldLiteral:
				e.BoundFields = append(e.BoundFields, lhs)
			case *FieldLiteral:
				field := fields.Field(lhs.Value)
				switch v := expr.RHS.(type) {
				case *StringLiteral:
					stringFields[field] = append(stringFields[field], v.Value)
				case *ListLiteral:
					stringFields[field] = append(stringFields[field], v.Values...)
				}
			}
			switch rhs := expr.RHS.(type) {
			case *BoundFieldLiteral:
				e.BoundFields = append(e.BoundFields, rhs)
			case *FieldLiteral:
				field := fields.Field(rhs.Value)
				switch v := expr.LHS.(type) {
				case *StringLiteral:
					stringFields[field] = append(stringFields[field], v.Value)
				case *ListLiteral:
					stringFields[field] = append(stringFields[field], v.Values...)
				}
			}
		}
	}
	WalkFunc(e.Expr, walk)

	// initialize event type/category buckets for every such field
	for name, values := range stringFields {
		if name == fields.KevtName || name == fields.KevtCategory {
			for _, v := range values {
				e.buckets[hashers.FnvUint32([]byte(v))] = true
			}
		}
	}
}

// IsEvaluable determines if the expression should be evaluated by inspecting
// the event type filter fields defined in the expression. We permit the expression
// to be evaluated when the incoming event type or category pertains to the one
// defined in the field literal.
func (e *SequenceExpr) IsEvaluable(kevt *kevent.Kevent) bool {
	return e.buckets[kevt.Type.Hash()] || e.buckets[kevt.Category.Hash()]
}

// HasBoundFields determines if this sequence expression has bound fields.
func (e *SequenceExpr) HasBoundFields() bool {
	return len(e.BoundFields) > 0
}

// Sequence is a collection of two or more sequence expressions.
type Sequence struct {
	MaxSpan     time.Duration
	By          fields.Field
	Expressions []SequenceExpr
}

// IsConstrained determines if the sequence has the global or per-expression `BY` statement.
func (s Sequence) IsConstrained() bool {
	return !s.By.IsEmpty() || !s.Expressions[0].By.IsEmpty()
}

func (s Sequence) impairBy() bool {
	b := make(map[bool]int, len(s.Expressions))
	for _, expr := range s.Expressions {
		b[!expr.By.IsEmpty()]++
	}
	if !s.By.IsEmpty() && (b[true] == len(s.Expressions) || b[false] == len(s.Expressions)) {
		return false
	}
	return b[true] > 0 && b[false] > 0
}
