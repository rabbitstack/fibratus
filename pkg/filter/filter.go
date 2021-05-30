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

package filter

import (
	"errors"
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"strings"
)

var (
	accessorErrors = expvar.NewMap("filter.accessor.errors")
	errNoFields    = errors.New("expected at least one field or operator but zero found")
)

// Filter is the main interface for the filter engine implementors.
type Filter interface {
	// Compile compiles the filter by parsing the filtering expression.
	Compile() error
	// Run runs a filter on the inbound kernel event and decides whether the event should be dropped or propagated to the downstream channel.
	Run(kevt *kevent.Kevent) bool
}

type filter struct {
	expr      ql.Expr
	parser    *ql.Parser
	accessors []accessor
	fields    []fields.Field
	// multivaluer determines whether we should
	// rely on the multivaluer to supply args
	// for function calls or just use a simple
	// map valuer
	multivaluer bool
}

// New creates a new filter with the specified filter expression. The consumers must ensure
// the expression is correctly parsed before executing the filter. This is achieved by calling the
// Compile` method after constructing the filter.
func New(expr string, config *config.Config) Filter {
	accessors := []accessor{
		// general event parameters
		newKevtAccessor(),
		// process state and parameters
		newPSAccessor(),
	}
	kconfig := config.Kstream

	if kconfig.EnableThreadKevents {
		accessors = append(accessors, newThreadAccessor())
	}
	if kconfig.EnableImageKevents {
		accessors = append(accessors, newImageAccessor())
	}
	if kconfig.EnableFileIOKevents {
		accessors = append(accessors, newFileAccessor())
	}
	if kconfig.EnableRegistryKevents {
		accessors = append(accessors, newRegistryAccessor())
	}
	if kconfig.EnableNetKevents {
		accessors = append(accessors, newNetworkAccessor())
	}
	if kconfig.EnableHandleKevents {
		accessors = append(accessors, newHandleAccessor())
	}
	if config.PE.Enabled {
		accessors = append(accessors, newPEAccessor())
	}

	return &filter{
		parser:    ql.NewParser(expr),
		accessors: accessors,
		fields:    make([]fields.Field, 0),
	}
}

// NewFromCLI builds and compiles a filter by joining all the command line arguments into the filter expression.
func NewFromCLI(args []string, config *config.Config) (Filter, error) {
	expr := strings.Join(args, " ")
	if expr == "" {
		return nil, nil
	}
	filter := New(expr, config)
	if err := filter.Compile(); err != nil {
		return nil, fmt.Errorf("bad filter: \n  %v", err)
	}
	return filter, nil
}

// NewFromCLIWithAllAccessors builds and compiles a filter with all field accessors enabled.
func NewFromCLIWithAllAccessors(args []string) (Filter, error) {
	expr := strings.Join(args, " ")
	if expr == "" {
		return nil, nil
	}
	filter := &filter{
		parser:    ql.NewParser(expr),
		accessors: getAccessors(),
		fields:    make([]fields.Field, 0),
	}
	if err := filter.Compile(); err != nil {
		return nil, fmt.Errorf("bad filter: \n  %v", err)
	}
	return filter, nil
}

// Compile parsers the filter expression and builds a binary expression tree
// where leaf nodes represent constants/variables while internal nodes are
// operators. Operators can be binary (=) or unary (not). Fields in filter
// expressions are replaced with respective event parameters via map valuer.
// For functions call we grab all the arguments that are evaluated as field
// literals.
// Matching the filter involves descending the binary expression tree recursively
// until all nodes are visited.
func (f *filter) Compile() error {
	var err error
	f.expr, err = f.parser.ParseExpr()
	if err != nil {
		return err
	}

	ql.WalkFunc(f.expr, func(n ql.Node) {
		if expr, ok := n.(*ql.BinaryExpr); ok {
			if lhs, ok := expr.LHS.(*ql.FieldLiteral); ok {
				f.fields = append(f.fields, fields.Field(lhs.Value))
			}
			if rhs, ok := expr.RHS.(*ql.FieldLiteral); ok {
				f.fields = append(f.fields, fields.Field(rhs.Value))
			}
		}
		if expr, ok := n.(*ql.Function); ok {
			f.multivaluer = true
			for _, arg := range expr.Args {
				if fld, ok := arg.(*ql.FieldLiteral); ok {
					f.fields = append(f.fields, fields.Field(fld.Value))
				}
			}
		}
	})

	if len(f.fields) == 0 {
		return errNoFields
	}

	return nil
}

func (f *filter) Run(kevt *kevent.Kevent) bool {
	if f.expr == nil {
		return false
	}
	valuer := make(map[string]interface{})
	// for each field present in the AST, we run the
	// accessors and extract the field vales that are
	// supplied to the valuer. The valuer feeds the
	// expression with correct values.
	for _, field := range f.fields {
		for _, accessor := range f.accessors {
			v, err := accessor.get(field, kevt)
			if err != nil && !kerrors.IsKparamNotFound(err) {
				accessorErrors.Add(err.Error(), 1)
				continue
			}
			if v == nil {
				continue
			}
			valuer[field.String()] = v
		}
	}
	return ql.Eval(f.expr, valuer, f.multivaluer)
}
