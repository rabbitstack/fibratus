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
	"net"
	"reflect"
	"strconv"
	"strings"

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
func (f Function) validate() error {
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
		case reflect.TypeOf(&IPLiteral{}):
			typ = functions.IP
		case reflect.TypeOf(&StringLiteral{}):
			typ = functions.String
		case reflect.TypeOf(&IntegerLiteral{}):
			typ = functions.Number
		case reflect.TypeOf(&Function{}):
			typ = functions.Func
		}

		if !arg.ContainsType(typ) {
			return ErrArgumentTypeMismatch(i, arg.Keyword, fn.Name(), arg.Types)
		}
	}
	return nil
}
