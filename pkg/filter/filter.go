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
	// ErrNoFields signals an error that happens when the filter is declared without any fields
	ErrNoFields = errors.New("expected at least one field or operator but zero found")
	// accessorErrors counts the errors produced by the field accessors
	accessorErrors = expvar.NewMap("filter.accessor.errors")
)

// Filter is the main interface for the filter engine implementors. Filter can either
// be a single expression combined by various subexpressions connected by operators, or
// it can be a sequence of expressions.
type Filter interface {
	// Compile compiles the filter by parsing the sequence/expression.
	Compile() error
	// Run runs a filter with a single expression. The return value decides
	// if the incoming event has successfully matched the filter expression.
	Run(kevt *kevent.Kevent) bool
	// RunSequence runs a filter with sequence expressions. Sequence rules depend
	// on the state machine transitions and partial matches to decide whether the
	// rule is fired.
	RunSequence(kevt *kevent.Kevent, seqID uint16, partials map[uint16][]*kevent.Kevent, rawMatch bool) bool
	// GetStringFields returns field names mapped to their string values.
	GetStringFields() map[fields.Field][]string
	// GetFields returns all field used in the filter expression.
	GetFields() []fields.Field
	// GetSequence returns the sequence descriptor or nil if this filter is not a sequence.
	GetSequence() *ql.Sequence
	// IsSequence determines if this filter is a sequence.
	IsSequence() bool
}

type filter struct {
	expr        ql.Expr
	seq         *ql.Sequence
	parser      *ql.Parser
	accessors   []Accessor
	fields      []fields.Field
	boundFields []*ql.BoundFieldLiteral
	// stringFields contains filter field names mapped to their string values
	stringFields map[fields.Field][]string
	hasFunctions bool
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
	if f.parser.IsSequence() {
		f.seq, err = f.parser.ParseSequence()
	} else {
		f.expr, err = f.parser.ParseExpr()
	}
	if err != nil {
		return err
	}

	// traverse the expression tree
	walk := func(n ql.Node) {
		switch expr := n.(type) {
		case *ql.BinaryExpr:
			if lhs, ok := expr.LHS.(*ql.FieldLiteral); ok {
				field := fields.Field(lhs.Value)
				f.addField(field)
				f.addStringFields(field, expr.RHS)
			}
			if rhs, ok := expr.RHS.(*ql.FieldLiteral); ok {
				field := fields.Field(rhs.Value)
				f.addField(field)
				f.addStringFields(field, expr.LHS)
			}
			if lhs, ok := expr.LHS.(*ql.BoundFieldLiteral); ok {
				f.addBoundField(lhs)
			}
			if rhs, ok := expr.RHS.(*ql.BoundFieldLiteral); ok {
				f.addBoundField(rhs)
			}
		case *ql.Function:
			f.hasFunctions = true
			for _, arg := range expr.Args {
				if field, ok := arg.(*ql.FieldLiteral); ok {
					f.addField(fields.Field(field.Value))
				}
				if field, ok := arg.(*ql.BoundFieldLiteral); ok {
					f.addBoundField(field)
				}
			}
		case *ql.FieldLiteral:
			field := fields.Field(expr.Value)
			if fields.IsBoolean(field) {
				f.addField(field)
			}
		}
	}
	if f.expr != nil {
		ql.WalkFunc(f.expr, walk)
	} else {
		if !f.seq.By.IsEmpty() {
			f.addField(f.seq.By)
		}
		for _, expr := range f.seq.Expressions {
			ql.WalkFunc(expr.Expr, walk)
			if !expr.By.IsEmpty() {
				f.addField(expr.By)
			}
		}
	}
	if len(f.fields) == 0 && !f.hasFunctions {
		return ErrNoFields
	}
	// only retain accessors for declared filter fields
	f.narrowAccessors()
	return f.checkBoundRefs()
}

func (f *filter) Run(kevt *kevent.Kevent) bool {
	if f.expr == nil {
		return false
	}
	return ql.Eval(f.expr, f.mapValuer(kevt), f.hasFunctions)
}

func (f *filter) RunSequence(kevt *kevent.Kevent, seqID uint16, partials map[uint16][]*kevent.Kevent, rawMatch bool) bool {
	if f.seq == nil {
		return false
	}
	nseqs := uint16(len(f.seq.Expressions))
	if seqID > nseqs-1 {
		return false
	}
	valuer := f.mapValuer(kevt)
	expr := f.seq.Expressions[seqID]

	if rawMatch {
		// only check if the condition matches
		// without evaluating joins/bound fields
		return ql.Eval(expr.Expr, valuer, f.hasFunctions)
	}
	var match bool
	if seqID >= 1 && expr.HasBoundFields() {
		// if a sequence expression contains references to
		// bound fields we map all partials to their sequence
		// aliases
		p := make(map[string][]*kevent.Kevent)
		nslots := len(partials[seqID])
		for i := uint16(0); i < seqID; i++ {
			alias := f.seq.Expressions[i].Alias
			if alias == "" {
				continue
			}
			p[alias] = partials[i+1]
			if len(p[alias]) > nslots {
				nslots = len(p[alias])
			}
		}
		// process until partials from all slots are consumed
		n := 0
		for nslots > 0 {
			nslots--
			for _, field := range expr.BoundFields {
				evts := p[field.Alias()]
				var evt *kevent.Kevent
				if n > len(evts)-1 {
					// pick the latest event if all
					// events for this slot are consumed
					evt = evts[len(evts)-1]
				} else {
					evt = evts[n]
				}
				for _, accessor := range f.accessors {
					v, err := accessor.Get(field.Field(), evt)
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
			n++
			match = ql.Eval(expr.Expr, valuer, f.hasFunctions)
			if match {
				break
			}
		}
	} else {
		by := f.seq.By
		if by.IsEmpty() {
			by = expr.By
		}
		if seqID >= 1 && !by.IsEmpty() {
			// traverse upstream partials for join equality
			joins := make([]bool, seqID)
			joinID := valuer[by.String()]
		outer:
			for i := uint16(0); i < seqID; i++ {
				for _, p := range partials[i+1] {
					if compareSeqJoin(joinID, p.SequenceBy()) {
						joins[i] = true
						continue outer
					}
				}
			}
			match = joinsEqual(joins) && ql.Eval(expr.Expr, valuer, f.hasFunctions)
		} else {
			match = ql.Eval(expr.Expr, valuer, f.hasFunctions)
		}
		if match && !by.IsEmpty() {
			if v := valuer[by.String()]; v != nil {
				kevt.AddMeta(kevent.RuleSequenceByKey, v)
			}
		}
	}
	return match
}

func joinsEqual(joins []bool) bool {
	for _, j := range joins {
		if !j {
			return false
		}
	}
	return true
}

func (f *filter) GetStringFields() map[fields.Field][]string { return f.stringFields }
func (f *filter) GetFields() []fields.Field                  { return f.fields }

func (f *filter) IsSequence() bool          { return f.seq != nil }
func (f *filter) GetSequence() *ql.Sequence { return f.seq }

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
			for _, accessor := range GetAccessors() {
				var err error
				val, err = accessor.Get(fields.Field(m[2]), kevt)
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

// mapValuer for each field present in the AST, we run the
// accessors and extract the field values that are
// supplied to the valuer. The valuer feeds the
// expression with correct values.
func (f *filter) mapValuer(kevt *kevent.Kevent) map[string]interface{} {
	valuer := make(map[string]interface{}, len(f.fields))
	for _, field := range f.fields {
		for _, accessor := range f.accessors {
			if !accessor.IsFieldAccessible(kevt) {
				continue
			}
			v, err := accessor.Get(field, kevt)
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

// addField appends a new field to the filter fields list.
func (f *filter) addField(field fields.Field) {
	for _, f := range f.fields {
		if f.String() == field.String() {
			return
		}
	}
	f.fields = append(f.fields, field)
}

// addStringFields appends values for all string field expressions.
func (f *filter) addStringFields(field fields.Field, expr ql.Expr) {
	switch v := expr.(type) {
	case *ql.StringLiteral:
		f.stringFields[field] = append(f.stringFields[field], v.Value)
	case *ql.ListLiteral:
		f.stringFields[field] = append(f.stringFields[field], v.Values...)
	}
}

// addBoundField appends a new bound field
func (f *filter) addBoundField(field *ql.BoundFieldLiteral) {
	f.boundFields = append(f.boundFields, field)
}

// checkBoundRefs checks if the bound field is referencing a valid alias.
// If no valid alias is reference, this method returns an error specifying
// an incorrect alias reference.
func (f *filter) checkBoundRefs() error {
	if f.seq == nil {
		return nil
	}
	aliases := make(map[string]bool)
	for _, expr := range f.seq.Expressions {
		if expr.Alias == "" {
			continue
		}
		aliases[expr.Alias] = true
	}
	for _, field := range f.boundFields {
		if _, ok := aliases[field.Alias()]; !ok {
			return fmt.Errorf("%s bound field references "+
				"an invalid '$%s' event alias",
				field.String(), field.Alias())
		}
	}
	return nil
}
