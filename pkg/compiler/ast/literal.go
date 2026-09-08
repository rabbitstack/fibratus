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

package ast

import (
	"net"
	"reflect"
	"strconv"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"

	"github.com/rabbitstack/fibratus/pkg/compiler/functions"
)

// StringLiteral represents a string literal.
type StringLiteral struct {
	Value string
}

// FieldLiteral represents a field literal.
type FieldLiteral struct {
	Value string
	Field fields.Field
	Arg   string
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

// BoundFieldLiteral represents the bound field literal.
type BoundFieldLiteral struct {
	Value    string
	BoundVar BareBoundVariableLiteral
	Field    *FieldLiteral
}

// BoundSegmentLiteral represents the bound segment literal.
type BoundSegmentLiteral struct {
	Value    string
	BoundVar BareBoundVariableLiteral
	Segment  fields.Segment
}

type BareBoundVariableLiteral struct {
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

func (f *FieldLiteral) String() string {
	if f.Arg != "" {
		var b strings.Builder
		b.Grow(len(f.Value) + len(f.Arg) + 2)
		b.WriteString(f.Value)
		b.WriteByte('[')
		b.WriteString(f.Arg)
		b.WriteByte(']')
		return b.String()
	}
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

func (b BoundSegmentLiteral) String() string {
	return b.Value
}

func (b BareBoundVariableLiteral) String() string {
	return b.Value
}

// ListLiteral represents a list of tag key literals.
type ListLiteral struct {
	Values []string
}

// String returns a string representation of the literal.
func (s *ListLiteral) String() string {
	var n int
	for _, elem := range s.Values {
		n += len(elem) + 2
	}

	var b strings.Builder
	b.Grow(n + 2)
	b.WriteRune('(')

	for idx, elem := range s.Values {
		if idx != 0 {
			b.WriteString(", ")
		}
		b.WriteString(elem)
	}

	b.WriteRune(')')

	return b.String()
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
	args := strings.Join(f.ArgsSlice(), ", ")

	var b strings.Builder
	b.Grow(len(args) + len(f.Name) + 2)

	b.WriteString(f.Name)
	b.WriteRune('(')
	b.WriteString(args)
	b.WriteRune(')')

	// Write function name and args.
	return b.String()
}

func (f *Function) IsForeach() bool {
	return f.Name == "foreach" || f.Name == "FOREACH"
}

func (f *Function) IsBinaryExprArg(i int) bool {
	_, ok := f.Args[i].(*BinaryExpr)
	return ok
}

func (f *Function) IsNotExprArg(i int) bool {
	_, ok := f.Args[i].(*NotExpr)
	return ok
}

func (f *Function) IsBareBoundVariableArg(i int) bool {
	_, ok := f.Args[i].(*BareBoundVariableLiteral)
	return ok
}

func (f *Function) IsFieldArg(i int) bool {
	_, ok := f.Args[i].(*FieldLiteral)
	return ok
}

// validate ensures that the function name obtained
// from the parser exists within the internal functions
// catalog. It also validates the function signature to
// make sure required arguments are supplied. Finally, it
// checks the type of each argument with the expected one.
func (f *Function) Validate() error {
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
		case reflect.TypeOf(&FieldLiteral{}):
			typ = functions.Field
		case reflect.TypeOf(&BoundFieldLiteral{}):
			typ = functions.BoundField
		case reflect.TypeOf(&BoundSegmentLiteral{}):
			typ = functions.BoundSegment
		case reflect.TypeOf(&BareBoundVariableLiteral{}):
			typ = functions.BareBoundVariable
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
		case reflect.TypeOf(&BoolLiteral{}):
			typ = functions.Bool
		case reflect.TypeOf(&BinaryExpr{}), reflect.TypeOf(&ParenExpr{}), reflect.TypeOf(&NotExpr{}):
			typ = functions.Expression
		}

		if !arg.ContainsType(typ) {
			return ErrArgumentTypeMismatch(i, arg.Keyword, fn.Name(), arg.Types)
		}
	}

	return nil
}

// SequenceStep represents a single expression within the sequence.
type SequenceStep struct {
	// Expr is the expression that belongs to the sequence step.
	Expr Expr
	// By contains the sequence step link if the sequence is constrained.
	By       *SequenceLink
	BoundVar string
}

// SequenceLink represents a single or
// a collection of fields that are used to
// build the sequence join link.
type SequenceLink struct {
	Fields []*FieldLiteral
}

// IsCompound indicates if the sequence expression
// uses multiple fields for the join link.
func (l *SequenceLink) IsCompound() bool {
	return len(l.Fields) > 1
}

// First returns the first field if the link is not compound.
func (l *SequenceLink) First() string {
	if len(l.Fields) == 1 {
		return l.Fields[0].Value
	}
	return ""
}

// IsConstrained determines if the sequence has the global or per-expression `BY` statement.
func (s SequenceExpr) IsConstrained() bool {
	return s.By != nil || (len(s.Steps) > 0 && s.Steps[0].By != nil)
}

// HasIncompatibleConstraints checks if the sequence has
// both global and per-expression `BY` statements mixed
// and returns true if such condition is satisfied.
func (s SequenceExpr) HasIncompatibleConstraints() bool {
	for _, step := range s.Steps {
		if step.By != nil && s.By != nil {
			return true
		}
	}
	return false
}

// HasImpairBy returns true if the sequence has impair
// count of BY statements.
func (s SequenceExpr) HasImpairBy() bool {
	b := make(map[bool]int, len(s.Steps))
	for _, step := range s.Steps {
		b[step.By != nil]++
	}
	if s.By != nil && (b[true] == len(s.Steps) || b[false] == len(s.Steps)) {
		return false
	}
	return b[true] > 0 && b[false] > 0
}
