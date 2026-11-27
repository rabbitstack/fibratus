/*
 * Copyright 2026 by Nedim Sabic Sabic
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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFunctionValidate(t *testing.T) {
	var tests = []struct {
		name string
		fn   *Function
		ok   bool
	}{
		{"lower", &Function{Name: "lower", Args: []Expr{&StringLiteral{Value: "A"}}}, true},
		{"case", &Function{Name: "LoWeR", Args: []Expr{&StringLiteral{Value: "A"}}}, true},
		{"undefined", &Function{Name: "nope", Args: []Expr{&StringLiteral{Value: "A"}}}, false},
		{"missing arguments", &Function{Name: "ltrim", Args: []Expr{&StringLiteral{Value: "A"}}}, false},
		{"too many arguments", &Function{Name: "lower", Args: []Expr{&StringLiteral{Value: "A"}, &StringLiteral{Value: "B"}}}, false},
		{"argument type", &Function{Name: "lower", Args: []Expr{&BoolLiteral{Value: true}}}, false},
		{"symlink", &Function{Name: "symlink", Args: []Expr{&StringLiteral{Value: "a"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn.Validate()
			if tt.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestUndefinedFunctionListsTheFunctions(t *testing.T) {
	err := (&Function{Name: "nope"}).Validate()
	assert.ErrorContains(t, err, "LTRIM")
	assert.ErrorContains(t, err, "RTRIM")
}
