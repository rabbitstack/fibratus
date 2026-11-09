/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package rules

import (
	"slices"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
	"github.com/rabbitstack/fibratus/pkg/eval"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
)

// Approvers narrow down the high-volume events (registry key opens, file
// opens, process/thread opens) before they are materialized into event
// structures, so the event source can discard the events no rule is interested
// in as early as possible.
//
// Approvers know nothing about the event source internals. They are keyed by
// the event type and expressed in terms of the rule fields. The consumer
// supplies the attribute values lazily, through a ValueFunc, and only the
// attributes the approvers ask for are ever resolved.
//
// An event is approved if any approver of its type approves it. Each
// approver is derived from the condition of a single rule (or a sequence
// step), and it is the conjunction of the predicates that must hold for the rule
// to match. If a rule that consumes the event type has no predicate
// the approvers can evaluate, the events of that type can't be narrowed
// down, and they are all approved. The event types that no approver
// is registered for are approved too. Approvers never reject more than
// what the rules would have rejected anyway.
type Approvers struct {
	byType map[event.Type]*typeApprovers
}

type typeApprovers struct {
	// all signals the events can't be narrowed down
	all  bool
	list []Approver
	seen map[string]struct{}
}

// Key identifies the event attribute an approver matches against.
type Key struct {
	// Field is the rule field, e.g. file.path.
	Field fields.Field
	// Arg is the name of the event parameter for the evt.arg field.
	Arg string
}

// String returns the key in the rule condition syntax.
func (k Key) String() string {
	if k.Arg != "" {
		return string(k.Field) + "[" + k.Arg + "]"
	}
	return string(k.Field)
}

// ValueFunc resolves the value of the event attribute. The second return
// value is false if the value can't be resolved. An approver that can't
// resolve the value it needs doesn't reject the event.
type ValueFunc func(Key) (string, bool)

// FieldMatcher binds the matcher to the attribute it is evaluated against.
type FieldMatcher struct {
	Key     Key
	Matcher Matcher
}

// Approver is the conjunction of the predicates that must hold
// for an event to be matched by a single rule condition.
type Approver struct {
	Matchers []FieldMatcher
}

// Approve returns false if any of the matchers rejects the attribute value.
func (a Approver) Approve(value ValueFunc) bool {
	for _, m := range a.Matchers {
		v, ok := value(m.Key)
		if !ok {
			continue
		}
		if !m.Matcher.Match(v) {
			return false
		}
	}
	return true
}

// String returns the approver in the rule condition syntax.
func (a Approver) String() string {
	preds := make([]string, 0, len(a.Matchers))
	for _, m := range a.Matchers {
		preds = append(preds, m.Key.String()+" "+m.Matcher.String())
	}
	return strings.Join(preds, " and ")
}

// ApproverCaps tells the rule set which event attributes the event
// source is able to resolve before the event is materialized.
type ApproverCaps struct {
	// Keys are the attributes available for the event type.
	// The events types without keys can't be approved.
	Keys map[event.Type][]Key
	// DependsOn declares that the event of the key type is only
	// consumable if the events of the value types are kept around, e.g.
	// the file deletion needs the file open event to learn the file path.
	// A rule that consumes the key type approves all events of the value
	// types because their attributes may not be those of the rule.
	DependsOn map[event.Type][]event.Type
}

// DefaultApproverCaps returns the capabilities of the event source.
func DefaultApproverCaps() ApproverCaps {
	execKey := Key{Field: fields.EvtArg, Arg: params.Exe}
	return ApproverCaps{
		Keys: map[event.Type][]Key{
			event.RegOpenKey: {{Field: fields.RegistryPath}},
			event.CreateFile: {
				{Field: fields.FilePath},
				{Field: fields.FileName},
				{Field: fields.FileExtension},
				{Field: fields.FileOperation},
			},
			event.OpenProcess: {execKey},
			event.OpenThread:  {execKey},
		},
		DependsOn: map[event.Type][]event.Type{
			event.SetFileInformation: {event.CreateFile},
			event.DeleteFile:         {event.CreateFile},
			event.RenameFile:         {event.CreateFile},
		},
	}
}

// ApproversProvider supplies the current approvers. The rule engine implements
// it, so consumers always see the approvers of the most recently loaded rule
// set after the rules are reloaded.
type ApproversProvider interface {
	// Approvers returns the approvers of the current rule set.
	Approvers() *Approvers
}

// Approve determines if the event of the given type has to be
// processed further. The values of the event attributes are resolved lazily
// by the value function.
func (a *Approvers) Approve(typ event.Type, value ValueFunc) bool {
	if a == nil {
		return true
	}
	ta, ok := a.byType[typ]
	if !ok || ta.all {
		return true
	}
	for _, ap := range ta.list {
		if ap.Approve(value) {
			return true
		}
	}
	return false
}

// Narrows determines if there are approvers that can reject the events of the type.
func (a *Approvers) Narrows(typ event.Type) bool {
	if a == nil {
		return false
	}
	ta, ok := a.byType[typ]
	return ok && !ta.all
}

// For returns the approvers for the event type. It is empty
// if all the events are approved.
func (a *Approvers) For(typ event.Type) []Approver {
	if !a.Narrows(typ) {
		return nil
	}
	return a.byType[typ].list
}

// Types returns the event types that have registered approvers, whether they
// narrow the events down or approve all of them.
func (a *Approvers) Types() []event.Type {
	if a == nil {
		return nil
	}
	types := make([]event.Type, 0, len(a.byType))
	for typ := range a.byType {
		types = append(types, typ)
	}
	slices.SortFunc(types, func(x, y event.Type) int { return strings.Compare(x.String(), y.String()) })
	return types
}

// String returns the string representation of approvers.
func (a *Approvers) String() string {
	var sb strings.Builder
	for _, typ := range a.Types() {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		sb.WriteString(typ.String())
		ta := a.byType[typ]
		if ta.all {
			sb.WriteString(": all")
			continue
		}
		parts := make([]string, 0, len(ta.list))
		for _, ap := range ta.list {
			parts = append(parts, "("+ap.String()+")")
		}
		sb.WriteString(": " + strings.Join(parts, " or "))
	}
	return sb.String()
}

func (a *Approvers) entry(typ event.Type) *typeApprovers {
	ta, ok := a.byType[typ]
	if !ok {
		ta = &typeApprovers{seen: make(map[string]struct{})}
		a.byType[typ] = ta
	}
	return ta
}

func (a *Approvers) approveAll(typ event.Type) {
	ta := a.entry(typ)
	ta.all = true
	ta.list, ta.seen = nil, nil
}

func (a *Approvers) add(typ event.Type, ap Approver) {
	if len(ap.Matchers) == 0 {
		a.approveAll(typ)
		return
	}
	ta := a.entry(typ)
	if ta.all {
		return
	}
	s := ap.String()
	if _, ok := ta.seen[s]; ok {
		return
	}
	ta.seen[s] = struct{}{}
	ta.list = append(ta.list, ap)
}

// computeApprovers derives the approvers from the rules. Every sequence
// step is considered on its own, since each step consumes its own events.
func computeApprovers(rules []*Rule, caps ApproverCaps) *Approvers {
	a := &Approvers{byType: make(map[event.Type]*typeApprovers)}

	for _, r := range rules {
		for _, expr := range ruleExprs(r) {
			scope, ok := eval.ScopeOf(expr)
			if !ok {
				continue
			}
			leaves := conjuncts(expr, nil)
			for _, typ := range scope.Types() {
				if keys := caps.Keys[typ]; len(keys) > 0 {
					a.add(typ, buildApprover(leaves, keys))
				}
				for _, dep := range caps.DependsOn[typ] {
					if len(caps.Keys[dep]) > 0 {
						a.approveAll(dep)
					}
				}
			}
		}
	}

	return a
}

// buildApprover turns the necessary comparisons that the event
// source can resolve into matchers.
func buildApprover(leaves []*ast.BinaryExpr, keys []Key) Approver {
	var ap Approver
	for _, l := range leaves {
		f, ok := l.LHS.(*ast.FieldLiteral)
		if !ok {
			continue
		}
		key := Key{Field: f.Field, Arg: f.Arg}
		if !slices.Contains(keys, key) {
			continue
		}
		vals, ok := literalValues(l.RHS)
		if !ok {
			continue
		}
		m, ok := NewMatcher(l.Op, vals)
		if !ok {
			continue
		}
		ap.Matchers = append(ap.Matchers, FieldMatcher{Key: key, Matcher: m})
	}
	return ap
}

// ruleExprs returns the expressions that consume events independently.
func ruleExprs(r *Rule) []ast.Expr {
	expr := r.evaluator.GetExpr()
	if seq, ok := expr.(*ast.SequenceExpr); ok {
		exprs := make([]ast.Expr, 0, len(seq.Steps))
		for _, step := range seq.Steps {
			exprs = append(exprs, step.Expr)
		}
		return exprs
	}
	return []ast.Expr{expr}
}

// conjuncts flattens the comparisons that all have to hold for the
// expression to match, which are the ones reachable through the AND
// operators and parentheses. Comparisons under OR or NOT are not
// necessary conditions, so they can't be used to narrow the events.
func conjuncts(e ast.Expr, out []*ast.BinaryExpr) []*ast.BinaryExpr {
	switch n := e.(type) {
	case *ast.ParenExpr:
		return conjuncts(n.Expr, out)
	case *ast.BinaryExpr:
		if n.Op == lexer.And {
			out = conjuncts(n.LHS, out)
			return conjuncts(n.RHS, out)
		}
		return append(out, n)
	}
	return out
}

func literalValues(e ast.Expr) ([]string, bool) {
	switch v := e.(type) {
	case *ast.StringLiteral:
		return []string{v.Value}, true
	case *ast.ListLiteral:
		return v.Values, true
	}
	return nil, false
}
