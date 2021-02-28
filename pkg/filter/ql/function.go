/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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
	"github.com/rabbitstack/fibratus/pkg/filter/ql/functions"
	"reflect"
	"sort"
	"strings"
)

var (
	// ErrArgumentTypeMismatch signals an invalid argument type
	ErrArgumentTypeMismatch = func(i int, keyword string, fn functions.Fn, types []functions.ArgType) error {
		argTypes := make([]string, len(types))
		for i, typ := range types {
			argTypes[i] = typ.String()
		}
		return fmt.Errorf("argument #%d (%s) in function %s should be one of %v", i+1, keyword, fn, strings.Join(argTypes, "|"))
	}
	// ErrUndefinedFunction is thrown when an unknown function is supplied
	ErrUndefinedFunction = func(fn functions.Fn) error {
		return fmt.Errorf("%s function is undefined. Did you mean one of %s%s", fn, strings.Join(functionNames(), "|"), "?")
	}
	// ErrFunctionSignature is thrown when the function signature is not satisfied
	ErrFunctionSignature = func(desc functions.FunctionDesc, givenArguments int) error {
		return fmt.Errorf("%s function requires %d argument(s) but %d argument(s) given", desc.Name, desc.RequiredArgs(), givenArguments)
	}
)

var funcs = map[string]FunctionDef{
	functions.CIDRContainsFn.String(): &functions.CIDRContains{},
	functions.MD5Fn.String():          &functions.MD5{},
}

// FunctionDef is the interface that all function definitions have to satisfy.
type FunctionDef interface {
	// Call is the main function method that contains the implementation logic.
	Call(args []interface{}) (interface{}, bool)
	// Desc returns the function descriptor.
	Desc() functions.FunctionDesc
	// Name returns the function name.
	Name() functions.Fn
}

// FunctionValuer implements the CallValuer interface and delegates
// the evaluation of function calls to the corresponding functions.
type FunctionValuer struct {
	m map[string]interface{}
}

func (f FunctionValuer) Value(key string) (interface{}, bool) {
	v, ok := f.m[key]
	return v, ok
}

func (FunctionValuer) Call(name string, args []interface{}) (interface{}, bool) {
	fn, ok := funcs[strings.ToUpper(name)]
	if !ok {
		return nil, false
	}
	return fn.Call(args)
}

// checkFuncCall ensures that the function name obtained
// from the parser exists within the internal functions
// catalog. It also validates the function signature to
// make sure required arguments are supplied. Finally, it
// checks the type of each argument with the expected one.
func checkFuncCall(function *Function) error {
	fn, ok := funcs[strings.ToUpper(function.Name)]
	if !ok {
		return ErrUndefinedFunction(fn.Name())
	}

	if len(function.Args) < fn.Desc().RequiredArgs() ||
		len(function.Args) > len(fn.Desc().Args) {
		return ErrFunctionSignature(fn.Desc(), len(function.Args))
	}

	for i, expr := range function.Args {
		arg := fn.Desc().Args[i]
		if !arg.ContainsType(exprToArgumentType(expr)) {
			return ErrArgumentTypeMismatch(i, arg.Keyword, fn.Name(), arg.Types)
		}
	}
	return nil
}

func exprToArgumentType(expr Expr) functions.ArgType {
	switch reflect.TypeOf(expr) {
	case reflect.TypeOf(&FieldLiteral{}):
		return functions.Field
	case reflect.TypeOf(&IPLiteral{}):
		return functions.IP
	case reflect.TypeOf(&StringLiteral{}):
		return functions.String
	default:
		return functions.Unknown
	}
}

func functionNames() []string {
	names := make([]string, 0, len(funcs))
	for _, f := range funcs {
		names = append(names, f.Name().String())
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	return names
}
