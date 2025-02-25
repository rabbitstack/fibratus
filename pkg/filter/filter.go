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
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	"github.com/rabbitstack/fibratus/pkg/util/hashers"
	"net"
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
	Run(evt *kevent.Kevent) bool
	// RunSequence runs a filter with sequence expressions. Sequence rules depend
	// on the state machine transitions and partial matches to decide whether the
	// rule is fired.
	RunSequence(evt *kevent.Kevent, seqID int, partials map[int][]*kevent.Kevent, rawMatch bool) bool
	// GetStringFields returns field names mapped to their string values.
	GetStringFields() map[fields.Field][]string
	// GetFields returns all fields used in the filter expression.
	GetFields() []Field
	// GetSequence returns the sequence descriptor or nil if this filter is not a sequence.
	GetSequence() *ql.Sequence
	// IsSequence determines if this filter is a sequence.
	IsSequence() bool
}

// Field contains field meta attributes all accessors need to extract the value.
type Field struct {
	Name  fields.Field
	Value string
	Arg   string
}

// BoundField contains the field meta attributes in addition to bound field specific fields.
type BoundField struct {
	Field    Field
	Value    string
	BoundVar string
}

type filter struct {
	expr        ql.Expr
	seq         *ql.Sequence
	parser      *ql.Parser
	accessors   []Accessor
	fields      []Field
	segments    []fields.Segment
	boundFields []*ql.BoundFieldLiteral
	// seqBoundFields contains per-sequence bound fields resolved from bound field literals
	seqBoundFields map[int][]BoundField
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
				f.addField(lhs)
				f.addStringFields(lhs.Field, expr.RHS)
			}
			if rhs, ok := expr.RHS.(*ql.FieldLiteral); ok {
				f.addField(rhs)
				f.addStringFields(rhs.Field, expr.LHS)
			}
			if lhs, ok := expr.LHS.(*ql.BoundFieldLiteral); ok {
				f.addField(lhs.Field)
				f.addBoundField(lhs)
			}
			if rhs, ok := expr.RHS.(*ql.BoundFieldLiteral); ok {
				f.addField(rhs.Field)
				f.addBoundField(rhs)
			}
		case *ql.Function:
			f.hasFunctions = true
			for _, arg := range expr.Args {
				if field, ok := arg.(*ql.FieldLiteral); ok {
					f.addField(field)
				}
				if field, ok := arg.(*ql.BoundFieldLiteral); ok {
					f.addField(field.Field)
					f.addBoundField(field)
				}
				switch exp := arg.(type) {
				case *ql.BinaryExpr:
					if segment, ok := exp.LHS.(*ql.BoundSegmentLiteral); ok {
						f.addSegment(segment)
					}
					if segment, ok := exp.RHS.(*ql.BoundSegmentLiteral); ok {
						f.addSegment(segment)
					}
				}
			}
		case *ql.FieldLiteral:
			if fields.IsBoolean(expr.Field) {
				f.addField(expr)
			}
		}
	}

	if f.expr != nil {
		ql.WalkFunc(f.expr, walk)
	} else {
		if f.seq.By != nil {
			f.addField(f.seq.By)
		}
		for _, expr := range f.seq.Expressions {
			ql.WalkFunc(expr.Expr, walk)
			if expr.By != nil {
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

func (f *filter) Run(e *kevent.Kevent) bool {
	if f.expr == nil {
		return false
	}
	return ql.Eval(f.expr, f.mapValuer(e), f.hasFunctions)
}

func (f *filter) RunSequence(e *kevent.Kevent, seqID int, partials map[int][]*kevent.Kevent, rawMatch bool) bool {
	if f.seq == nil {
		return false
	}
	nseqs := len(f.seq.Expressions)
	if seqID > nseqs-1 {
		return false
	}
	valuer := f.mapValuer(e)
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
		for i := 0; i < seqID; i++ {
			alias := f.seq.Expressions[i].Alias
			if alias == "" {
				continue
			}
			p[alias] = partials[i]
			if len(p[alias]) > nslots {
				nslots = len(p[alias])
			}
		}

		flds, ok := f.seqBoundFields[seqID]
		if !ok {
			flds = f.addSeqBoundFields(seqID, expr.BoundFields)
		}

		// process until partials from all slots are consumed
		n := 0
		hash := make([]byte, 0)
		for nslots > 0 {
			nslots--
			var evt *kevent.Kevent
			for _, field := range flds {
				// get all events pertaining to the bounded event
				evts := p[field.BoundVar]
				if n > len(evts)-1 {
					// pick the latest event if all
					// events for this slot are consumed
					evt = evts[len(evts)-1]
				} else {
					evt = evts[n]
				}

				// resolve the bound field value
				for _, accessor := range f.accessors {
					if !accessor.IsFieldAccessible(evt) {
						continue
					}
					v, err := accessor.Get(field.Field, evt)
					if err != nil && !kerrors.IsKparamNotFound(err) {
						accessorErrors.Add(err.Error(), 1)
						continue
					}
					if v != nil {
						valuer[field.Value] = v
						switch val := v.(type) {
						case uint8:
							hash = append(hash, val)
						case uint16:
							hash = append(hash, bytes.WriteUint16(val)...)
						case uint32:
							hash = append(hash, bytes.WriteUint32(val)...)
						case uint64:
							hash = append(hash, bytes.WriteUint64(val)...)
						case int8:
							hash = append(hash, byte(val))
						case int16:
							hash = append(hash, bytes.WriteUint16(uint16(val))...)
						case int32:
							hash = append(hash, bytes.WriteUint32(uint32(val))...)
						case int64:
							hash = append(hash, bytes.WriteUint64(uint64(val))...)
						case int:
							hash = append(hash, bytes.WriteUint64(uint64(val))...)
						case uint:
							hash = append(hash, bytes.WriteUint64(uint64(val))...)
						case string:
							hash = append(hash, val...)
						case net.IP:
							hash = append(hash, val...)
						}
						break
					}
				}
			}
			n++
			match = ql.Eval(expr.Expr, valuer, f.hasFunctions)
			if match {
				// compute sequence key hash to tie the events
				evt.AddMeta(kevent.RuleSequenceLink, hashers.FnvUint64(hash))
				e.AddMeta(kevent.RuleSequenceLink, hashers.FnvUint64(hash))
				break
			}
		}
	} else {
		by := f.seq.By
		if by == nil {
			by = expr.By
		}

		if seqID >= 1 && by != nil {
			// traverse upstream partials for join equality
			joins := make([]bool, seqID)
			joinID := valuer[by.Value]
		outer:
			for i := 0; i < seqID; i++ {
				for _, p := range partials[i] {
					if CompareSeqLink(joinID, p.SequenceLink()) {
						joins[i] = true
						continue outer
					}
				}
			}
			match = joinsEqual(joins) && ql.Eval(expr.Expr, valuer, f.hasFunctions)
		} else {
			match = ql.Eval(expr.Expr, valuer, f.hasFunctions)
		}

		if match && by != nil {
			if v := valuer[by.Value]; v != nil {
				e.AddMeta(kevent.RuleSequenceLink, v)
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
func (f *filter) GetFields() []Field                         { return f.fields }

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
				f := Field{Value: m[2], Name: fields.Field(m[2])}
				val, err = accessor.Get(f, kevt)
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
func (f *filter) mapValuer(evt *kevent.Kevent) map[string]interface{} {
	valuer := make(map[string]interface{}, len(f.fields))
	for _, field := range f.fields {
		for _, accessor := range f.accessors {
			if !accessor.IsFieldAccessible(evt) {
				continue
			}
			v, err := accessor.Get(field, evt)
			if err != nil && !kerrors.IsKparamNotFound(err) {
				accessorErrors.Add(err.Error(), 1)
				continue
			}
			if v != nil {
				valuer[field.Value] = v
				break
			}
		}
	}
	return valuer
}

// addField appends a new field to the filter fields list.
func (f *filter) addField(field *ql.FieldLiteral) {
	for _, f := range f.fields {
		if f.Value == field.Value {
			return
		}
	}
	f.fields = append(f.fields, Field{Value: field.Value, Name: field.Field, Arg: field.Arg})
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

// addBoundField appends a new bound field.
func (f *filter) addBoundField(field *ql.BoundFieldLiteral) {
	f.boundFields = append(f.boundFields, field)
}

// addSegment adds a new bound segment.
func (f *filter) addSegment(segment *ql.BoundSegmentLiteral) {
	f.segments = append(f.segments, segment.Segment)
}

// addSeqBoundFields receives the sequence id and the list of bound field literals
// and populates the list of bound fields containing the field structure convenient
// for accessors.
func (f *filter) addSeqBoundFields(seqID int, fields []*ql.BoundFieldLiteral) []BoundField {
	flds := make([]BoundField, 0, len(fields))
	for _, field := range fields {
		flds = append(flds,
			BoundField{
				Field:    Field{Name: field.Field.Field, Value: field.Field.Value, Arg: field.Field.Arg},
				Value:    field.Value,
				BoundVar: field.BoundVar.Value,
			})
	}
	f.seqBoundFields[seqID] = flds
	return flds
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
		if _, ok := aliases[field.BoundVar.Value]; !ok {
			return fmt.Errorf("%s bound field references "+
				"an invalid '$%s' event alias",
				field.String(), field.BoundVar.Value)
		}
	}

	return nil
}

// CompareSeqLink returns true if both values
// representing the sequence joins are equal.
func CompareSeqLink(s1, s2 any) bool {
	if s1 == nil || s2 == nil {
		return false
	}
	switch v := s1.(type) {
	case string:
		s, ok := s2.(string)
		if !ok {
			return false
		}
		return strings.EqualFold(v, s)
	case uint8:
		n, ok := s2.(uint8)
		if !ok {
			return false
		}
		return v == n
	case uint16:
		n, ok := s2.(uint16)
		if !ok {
			return false
		}
		return v == n
	case uint32:
		n, ok := s2.(uint32)
		if !ok {
			return false
		}
		return v == n
	case uint64:
		n, ok := s2.(uint64)
		if !ok {
			return false
		}
		return v == n
	case int:
		n, ok := s2.(int)
		if !ok {
			return false
		}
		return v == n
	case uint:
		n, ok := s2.(uint)
		if !ok {
			return false
		}
		return v == n
	case net.IP:
		ip, ok := s2.(net.IP)
		if !ok {
			return false
		}
		return v.Equal(ip)
	}
	return false
}
