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

package ast

import (
	"fmt"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/functions"
)

var (
	// ErrArgumentTypeMismatch signals an invalid argument type
	ErrArgumentTypeMismatch = func(i int, keyword string, fn functions.Fn, types []functions.ArgType) error {
		argTypes := make([]string, len(types))
		for i, typ := range types {
			argTypes[i] = typ.String()
		}
		return fmt.Errorf("argument #%d (%s) in function %s should be one of: %v", i+1, keyword, fn, strings.Join(argTypes, "|"))
	}
	// ErrUndefinedFunction is thrown when an unknown function is supplied
	ErrUndefinedFunction = func(name string) error {
		return fmt.Errorf("%s function is undefined. Did you mean one of %s%s", name, strings.Join(functions.Names(), "|"), "?")
	}
	// ErrFunctionSignature is thrown when the function signature is not satisfied
	ErrFunctionSignature = func(desc functions.FunctionDesc, givenArguments int) error {
		return fmt.Errorf("%s function requires %d argument(s) but %d argument(s) given", desc.Name, desc.RequiredArgs(), givenArguments)
	}
)
