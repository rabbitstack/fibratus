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
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"regexp"
	"strconv"
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
	// Run runs a filter on the inbound kernel event and decides whether the event
	// should be dropped or propagated to the downstream channel.
	Run(kevt *kevent.Kevent) bool
	// RunPartials runs a filter with stateful event tracking. Partials store all
	// intermediate events that are the result of previous filter matches.
	RunPartials(kevt *kevent.Kevent, partials map[uint16][]*kevent.Kevent) (bool, uint16, *kevent.Kevent)
	// BindingIndex returns the binding index to which the filter is bound
	// or a zero value if there are no pattern bindings defined.
	BindingIndex() (uint16, bool)
	// GetStringFields returns field names mapped to their string values
	GetStringFields() map[fields.Field][]string
}

type filter struct {
	expr      ql.Expr
	parser    *ql.Parser
	accessors []accessor
	fields    []fields.Field
	bindings  map[uint16][]*ql.PatternBindingLiteral
	// useFuncValuer determines whether we should supply the function valuer
	useFuncValuer bool
	// stringFields contains filter field names mapped to their string values
	stringFields map[fields.Field][]string
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

	walk := func(n ql.Node) {
		if expr, ok := n.(*ql.BinaryExpr); ok {
			if lhs, ok := expr.LHS.(*ql.FieldLiteral); ok {
				field := fields.Field(lhs.Value)
				f.fields = append(f.fields, field)
				switch v := expr.RHS.(type) {
				case *ql.StringLiteral:
					f.stringFields[field] = append(f.stringFields[field], v.Value)
				case *ql.ListLiteral:
					f.stringFields[field] = append(f.stringFields[field], v.Values...)
				}
			}
			if rhs, ok := expr.RHS.(*ql.FieldLiteral); ok {
				field := fields.Field(rhs.Value)
				f.fields = append(f.fields, field)
				switch v := expr.LHS.(type) {
				case *ql.StringLiteral:
					f.stringFields[field] = append(f.stringFields[field], v.Value)
				case *ql.ListLiteral:
					f.stringFields[field] = append(f.stringFields[field], v.Values...)
				}
			}
			if rhs, ok := expr.RHS.(*ql.PatternBindingLiteral); ok {
				f.bindings[rhs.Index()] = append(f.bindings[rhs.Index()], rhs)
			}
		}
		if expr, ok := n.(*ql.Function); ok {
			f.useFuncValuer = true
			for _, arg := range expr.Args {
				if fld, ok := arg.(*ql.FieldLiteral); ok {
					f.fields = append(f.fields, fields.Field(fld.Value))
				}
			}
		}
	}
	ql.WalkFunc(f.expr, walk)

	if len(f.fields) == 0 {
		return errNoFields
	}

	if len(f.bindings) > 1 {
		bindings := make([]string, 0)
		for _, b := range f.bindings {
			for _, binding := range b {
				bindings = append(bindings, binding.Value)
			}
		}
		return fmt.Errorf("multiple pattern bindings found referencing "+
			"distinct sequence events: %s", strings.Join(bindings, ","))
	}
	return nil
}

func (f *filter) Run(kevt *kevent.Kevent) bool {
	if f.expr == nil {
		return false
	}
	return ql.Eval(f.expr, f.mapValuer(kevt), nil, f.useFuncValuer)
}

func (f *filter) RunPartials(kevt *kevent.Kevent, partials map[uint16][]*kevent.Kevent) (bool, uint16, *kevent.Kevent) {
	if f.expr == nil {
		return false, 0, nil
	}
	mapValuer := f.mapValuer(kevt)
	i, ok := f.BindingIndex()
	if !ok {
		return false, 0, nil
	}
	kevts := partials[i]
	for _, e := range kevts {
		valuer := f.bindingValuer(e, i)
		ok := ql.Eval(f.expr, mapValuer, valuer, f.useFuncValuer)
		if ok {
			return true, i, e
		}
	}
	return false, 0, nil
}

func (f *filter) BindingIndex() (uint16, bool) {
	if len(f.bindings) == 0 {
		return 0, false
	}
	for i := range f.bindings {
		return i, true
	}
	return 0, false
}

func (f filter) GetStringFields() map[fields.Field][]string { return f.stringFields }

// mapValuer for each field present in the AST, we run the
// accessors and extract the field vales that are
// supplied to the valuer. The valuer feeds the
// expression with correct values.
func (f *filter) mapValuer(kevt *kevent.Kevent) map[string]interface{} {
	valuer := make(map[string]interface{}, len(f.fields))
	for _, field := range f.fields {
		for _, accessor := range f.accessors {
			v, err := accessor.get(field, kevt)
			if err != nil && !kerrors.IsKparamNotFound(err) {
				accessorErrors.Add(err.Error(), 1)
				continue
			}
			if v != nil {
				valuer[field.String()] = v
				break
			}
		}
	}
	return valuer
}

// bindingValuer for each pattern binding node, resolves its value from
// the event that pertains to the same pattern binding index.
func (f *filter) bindingValuer(kevt *kevent.Kevent, idx uint16) map[string]interface{} {
	valuer := make(map[string]interface{})
	for _, binding := range f.bindings[idx] {
		for _, accessor := range f.accessors {
			v, err := accessor.get(binding.Field(), kevt)
			if err != nil && !kerrors.IsKparamNotFound(err) {
				accessorErrors.Add(err.Error(), 1)
				continue
			}
			if v != nil {
				valuer[binding.Value] = v
				break
			}
		}
	}
	return valuer
}

// InterpolateFields replaces all occurrences of field modifiers in the given string
// with values extracted from the event. Field modifiers may contain a leading ordinal
// which refers to the event in particular sequence stage. Otherwise, the modifier is
// a well-known field name prepended with the `%` symbol.
func InterpolateFields(s string, evts []*kevent.Kevent) string {
	var fieldsReplRegexp = regexp.MustCompile(`%([1-9]?)\.?([a-z0-9A-Z\[\].]+)`)
	matches := fieldsReplRegexp.FindAllStringSubmatch(s, -1)
	r := s
	if len(matches) == 0 {
		return s
	}
	for _, m := range matches {
		switch {
		case len(m) == 3:
			// parse index if the field modifier
			// refers to the event in the sequence
			i := 1
			if m[1] != "" {
				var err error
				i, err = strconv.Atoi(m[1])
				if err != nil {
					continue
				}
			}
			if i-1 > len(evts)-1 {
				continue
			}
			kevt := evts[i-1]
			// extract field value from the event and replace in string
			var val any
			for _, accessor := range allAccessors() {
				var err error
				val, err = accessor.get(fields.Field(m[2]), kevt)
				if err != nil {
					continue
				}
				if val != nil {
					break
				}
			}
			if val != nil {
				r = strings.ReplaceAll(r, m[0], fmt.Sprintf("%v", val))
			} else {
				r = strings.ReplaceAll(r, m[0], "N/A")
			}
		default:
			return r
		}
	}
	return r
}
