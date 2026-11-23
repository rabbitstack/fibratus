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

package rules

import (
	"cmp"
	"maps"
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
// Approvers know nothing about the event source internals. They are expressed
// in terms of the rule fields, and the event source supplies the attribute
// values lazily through a Resolver, so only the attributes the approvers ask
// for are ever resolved.
//
// Events are narrowed down per Scope. The first level of scoping is the event
// type (evt.name = 'CreateFile'). The types that need it have a second level,
// the selector, which splits the events by the value of an attribute
// (file.operation = 'OPEN'). The scopes are independent. For example, the
// CreateFile events with the OPEN disposition are discarded if their path
// doesn't match the path of any rule that consumes them, while the CreateFile
// events with other dispositions are not affected at all.
//
// A scope is narrowed down by the approvers of the rules that consume its
// events. Each approver is the conjunction of the predicates the rule requires
// (file.path imatches '...') and an event of the scope is approved if any of
// its approvers approves it. The predicates are only extracted from the
// comparisons that are necessary for the rule to match. Comparisons under OR
// or NOT, such as file.path not imatches '...', yield nothing.
//
// A rule that may consume the events of the scope, but doesn't pin the
// selector to the value of the scope (no file.operation predicate at all, or
// file.operation in ('OPEN', 'CREATE')), or that has no predicate the
// approvers can evaluate, puts the scope in "accept-all" mode: every event of
// the scope is approved. Scopes that no approver is registered for are
// approved too. Approvers never reject more than what the rules would have
// rejected anyway.
//
// Approvers are immutable once computed, so they can be shared between
// goroutines without synchronization. Publish a new instance when the rules
// are reloaded (e.g. through an atomic.Pointer).
type Approvers struct {
	byType map[event.Type]typeApprovers
}

// Scope is the group of events that is narrowed down as a whole: the events of
// a type and, for the types that have a selector, the events with a particular
// value of the selector attribute.
type Scope struct {
	// Type is the event type.
	Type event.Type
	// Selector is the value of the selector attribute, e.g. OPEN for the
	// file.operation. It is empty for the types without a selector.
	Selector string
}

type typeApprovers struct {
	// selector is the attribute that splits the events of the type into
	// scopes. It is zero if the type has a single scope.
	selector Key
	// scopes are indexed by the value of the selector.
	scopes map[string]scopeApprovers
}

// lookup finds the scope the event falls in by resolving the selector. It
// returns false if the selector can't be resolved or the scope isn't registered.
func (ta typeApprovers) lookup(r Resolver) (scopeApprovers, bool) {
	var selector string
	if !ta.selector.isZero() {
		v, ok := r.Resolve(ta.selector)
		if !ok {
			return scopeApprovers{}, false
		}
		selector = v
	}
	sa, ok := ta.scopes[selector]
	return sa, ok
}

type scopeApprovers struct {
	// all signals the events of the scope can't be narrowed down.
	all bool
	// rule is the first rule that forced the accept-all mode.
	rule      *Rule
	approvers []Approver
}

// Key identifies the event attribute an approver matches against.
type Key struct {
	// Field is the rule field, e.g. file.path.
	Field fields.Field
	// Arg is the name of the event parameter for the evt.arg field.
	Arg string
}

func (k Key) isZero() bool { return k == Key{} }

// String returns the key in the rule condition syntax.
func (k Key) String() string {
	if k.Arg != "" {
		return string(k.Field) + "[" + k.Arg + "]"
	}
	return string(k.Field)
}

// keyOf returns the key of the field literal.
func keyOf(f *ast.FieldLiteral) Key { return Key{Field: f.Field, Arg: f.Arg} }

// Resolver resolves the value of an event attribute. The second return value
// is false if the value can't be resolved. An approver that can't resolve
// the value it needs doesn't reject the event.
//
// It is an interface rather than a bare func so the event source can pass a
// reusable struct and avoid allocating a closure per event in the ETW callback.
type Resolver interface {
	Resolve(Key) (string, bool)
}

// ResolverFunc adapts an ordinary function to the Resolver interface.
type ResolverFunc func(Key) (string, bool)

// Resolve calls f(k).
func (f ResolverFunc) Resolve(k Key) (string, bool) { return f(k) }

// FieldMatcher binds the matcher to the attribute it is evaluated against.
type FieldMatcher struct {
	Key     Key
	Matcher Matcher

	// cost orders the matchers within an approver, cheapest first, so
	// the expensive wildcard matches are skipped when a cheap predicate fails.
	cost int
}

// Approver is the conjunction of the predicates that must hold for an event of
// the scope to be matched by a single rule condition.
type Approver struct {
	Matchers []FieldMatcher
}

// Approve returns false if any of the matchers rejects the attribute value.
func (a Approver) Approve(r Resolver) bool {
	for _, m := range a.Matchers {
		v, ok := r.Resolve(m.Key)
		if ok && !m.Matcher.Match(v) {
			return false
		}
	}
	return true
}

// String returns the approver in the rule condition syntax.
func (a Approver) String() string {
	preds := make([]string, len(a.Matchers))
	for i, m := range a.Matchers {
		preds[i] = m.Key.String() + " " + m.Matcher.String()
	}
	return strings.Join(preds, " and ")
}

// EventCaps tells the rule set how the events of a single type can be
// narrowed down.
type EventCaps struct {
	// Selector is the attribute that splits the events of the type into
	// independent scopes, the second level of scoping after the event name,
	// e.g. file.operation for the CreateFile events. The zero value means the
	// type has a single scope.
	//
	// The selector is not an approver predicate. The rule conditions decide
	// which scope a rule belongs to (file.operation = 'OPEN'), and at runtime
	// the resolver tells which scope the event falls in.
	Selector Key
	// Keys are the attributes the event source can resolve before the event
	// is materialized, so they can be used as approver predicates, indexed by
	// the value of the selector (the empty value for the types without a
	// selector). The scopes that aren't listed are never narrowed down.
	Keys map[string][]Key
}

// unscoped returns the capabilities of the type that has a single scope.
func unscoped(keys ...Key) EventCaps {
	return EventCaps{Keys: map[string][]Key{"": keys}}
}

// ApproverCaps tells the rule set which event attributes the event
// source is able to resolve before the event is materialized.
type ApproverCaps struct {
	// Events are the capabilities of the event types that can be narrowed
	// down. The types that aren't listed can't be approved.
	Events map[event.Type]EventCaps
	// DependsOn declares that the event of the key type is only
	// consumable if the events of the value types are kept around, e.g.
	// the file deletion needs the file open event to learn the file path.
	// A rule that consumes the key type approves all events of the value
	// types because their attributes may not be those of the rule.
	DependsOn map[event.Type][]event.Type
}

// eventTypes returns every event type the capabilities mention.
func (c ApproverCaps) eventTypes() []event.Type {
	types := slices.AppendSeq(slices.Collect(maps.Keys(c.Events)), maps.Keys(c.DependsOn))
	// sorting makes the result deterministic and brings the duplicates together
	slices.SortFunc(types, func(x, y event.Type) int { return cmp.Compare(x.String(), y.String()) })
	return slices.Compact(types)
}

// DefaultApproverCaps returns the capabilities of the event source.
func DefaultApproverCaps() ApproverCaps {
	execKey := Key{Field: fields.EvtArg, Arg: params.Exe}
	return ApproverCaps{
		Events: map[event.Type]EventCaps{
			event.RegOpenKey:  unscoped(Key{Field: fields.RegistryPath}),
			event.OpenProcess: unscoped(execKey),
			event.OpenThread:  unscoped(execKey),
			// only the file opens are narrowed down by the path. Other
			// dispositions (create, overwrite, ...) are always approved.
			event.CreateFile: {
				Selector: Key{Field: fields.FileOperation},
				Keys: map[string][]Key{
					"OPEN": {
						{Field: fields.FilePath},
						{Field: fields.FileName},
						{Field: fields.FileExtension},
					},
				},
			},
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

// Approve determines if the event of the given type has to be processed
// further. The attribute values, including the selector that tells the scope
// of the event, are resolved lazily by the resolver. It is safe to call on a
// nil receiver, which approves everything.
func (a *Approvers) Approve(typ event.Type, r Resolver) bool {
	if a == nil {
		return true
	}
	ta, ok := a.byType[typ]
	if !ok {
		return true
	}
	sa, ok := ta.lookup(r)
	if !ok || sa.all {
		return true
	}
	for _, ap := range sa.approvers {
		if ap.Approve(r) {
			return true
		}
	}
	return false
}

func (a *Approvers) scope(s Scope) (scopeApprovers, bool) {
	if a == nil {
		return scopeApprovers{}, false
	}
	ta, ok := a.byType[s.Type]
	if !ok {
		return scopeApprovers{}, false
	}
	sa, ok := ta.scopes[s.Selector]
	return sa, ok
}

// Narrows determines if there are approvers that can reject the events of the scope.
func (a *Approvers) Narrows(s Scope) bool {
	sa, ok := a.scope(s)
	return ok && !sa.all
}

// For returns the approvers for the scope. It is empty
// if all the events of the scope are approved.
func (a *Approvers) For(s Scope) []Approver {
	if !a.Narrows(s) {
		return nil
	}
	sa, _ := a.scope(s)
	return sa.approvers
}

// AcceptAllRule returns the rule that prevented narrowing down the events
// of the given scope, or nil if the scope is narrowed down or has no approvers.
// It answers the "why isn't my file.path approver working" question.
func (a *Approvers) AcceptAllRule(s Scope) *Rule {
	sa, _ := a.scope(s)
	return sa.rule
}

// Scopes returns the scopes that have registered approvers, whether they
// narrow the events down or approve all of them.
func (a *Approvers) Scopes() []Scope {
	if a == nil {
		return nil
	}
	var scopes []Scope
	for typ, ta := range a.byType {
		for selector := range ta.scopes {
			scopes = append(scopes, Scope{Type: typ, Selector: selector})
		}
	}
	slices.SortFunc(scopes, func(x, y Scope) int {
		return cmp.Or(cmp.Compare(x.Type.String(), y.Type.String()), cmp.Compare(x.Selector, y.Selector))
	})
	return scopes
}

// String returns the string representation of approvers.
func (a *Approvers) String() string {
	var sb strings.Builder
	for _, s := range a.Scopes() {
		if sb.Len() > 0 {
			sb.WriteString("; ")
		}
		ta := a.byType[s.Type]
		sb.WriteString(s.Type.String())
		if !ta.selector.isZero() {
			sb.WriteString("[" + ta.selector.String() + " = '" + s.Selector + "']")
		}
		sa := ta.scopes[s.Selector]
		if sa.all {
			sb.WriteString(": all")
			continue
		}
		parts := make([]string, len(sa.approvers))
		for i, ap := range sa.approvers {
			parts[i] = "(" + ap.String() + ")"
		}
		sb.WriteString(": " + strings.Join(parts, " or "))
	}
	return sb.String()
}

// builder accumulates the approvers while the rules are scanned. It is
// separate from Approvers so the build-time state is not retained by the
// immutable result.
type builder struct {
	caps ApproverCaps
	// capTypes are all the event types the capabilities mention.
	capTypes []event.Type
	// typesOf returns the event types the expression consumes, or false if
	// they can't be determined. It is a field so the tests can replace it.
	typesOf func(ast.Expr) ([]event.Type, bool)
	byType  map[event.Type]*typeBuilder
}

type typeBuilder struct {
	selector Key
	scopes   map[string]*scopeBuilder
}

type scopeBuilder struct {
	all       bool
	rule      *Rule
	approvers []Approver
}

func newBuilder(caps ApproverCaps) *builder {
	return &builder{
		caps:     caps,
		capTypes: caps.eventTypes(),
		typesOf:  defaultTypesOf,
		byType:   make(map[event.Type]*typeBuilder),
	}
}

func (b *builder) entry(s Scope) *scopeBuilder {
	tb, ok := b.byType[s.Type]
	if !ok {
		tb = &typeBuilder{
			selector: b.caps.Events[s.Type].Selector,
			scopes:   make(map[string]*scopeBuilder),
		}
		b.byType[s.Type] = tb
	}
	sb, ok := tb.scopes[s.Selector]
	if !ok {
		sb = new(scopeBuilder)
		tb.scopes[s.Selector] = sb
	}
	return sb
}

// acceptAll switches the scope to accept-all mode, remembering the
// first rule responsible.
func (b *builder) acceptAll(s Scope, r *Rule) {
	sb := b.entry(s)
	if sb.all {
		return
	}
	sb.all, sb.rule = true, r
	sb.approvers = nil
}

// acceptAllScopes switches every scope of the event type that can be
// narrowed down to accept-all mode.
func (b *builder) acceptAllScopes(typ event.Type, r *Rule) {
	for selector := range b.caps.Events[typ].Keys {
		b.acceptAll(Scope{Type: typ, Selector: selector}, r)
	}
}

// add registers the approver of the rule. An approver without predicates can't
// narrow down the events.
func (b *builder) add(s Scope, ap Approver, r *Rule) {
	if len(ap.Matchers) == 0 {
		b.acceptAll(s, r)
		return
	}
	sb := b.entry(s)
	if sb.all {
		return
	}
	sb.approvers = append(sb.approvers, ap)
}

func (b *builder) build() *Approvers {
	a := &Approvers{byType: make(map[event.Type]typeApprovers, len(b.byType))}
	for typ, tb := range b.byType {
		ta := typeApprovers{
			selector: tb.selector,
			scopes:   make(map[string]scopeApprovers, len(tb.scopes)),
		}
		for selector, sb := range tb.scopes {
			// identical approvers (e.g. rules sharing the same file.path condition)
			// are folded into one. The order of the approvers doesn't affect the
			// outcome since an event is approved if any of them approves it. The
			// builder's slice is cloned so it stays usable after build.
			aps := slices.Clone(sb.approvers)
			slices.SortFunc(aps, func(x, y Approver) int { return cmp.Compare(x.String(), y.String()) })
			aps = slices.CompactFunc(aps, func(x, y Approver) bool { return x.String() == y.String() })
			ta.scopes[selector] = scopeApprovers{all: sb.all, rule: sb.rule, approvers: aps}
		}
		a.byType[typ] = ta
	}
	return a
}

// computeApprovers derives the approvers from the rules. Every sequence
// step is considered on its own, since each step consumes its own events.
// Only the enabled rules should be passed in.
func computeApprovers(rules []*Rule, caps ApproverCaps) *Approvers {
	b := newBuilder(caps)
	for _, r := range rules {
		b.addRule(r)
	}
	return b.build()
}

func defaultTypesOf(expr ast.Expr) ([]event.Type, bool) {
	scope := eval.NewScope(expr)
	return scope, !scope.IsUnbounded()
}

// addRule registers the approvers for every expression of the rule.
func (b *builder) addRule(r *Rule) {
	for _, expr := range b.exprs(r) {
		b.addExpr(r, expr)
	}
}

// addExpr registers the approvers for a single expression that consumes
// events on its own: a plain condition or a sequence step.
func (b *builder) addExpr(r *Rule, expr ast.Expr) {
	// If the types of the expression can't be determined (e.g. there is
	// no evt.name predicate), the rule may consume any event type, so
	// every type we could narrow must be treated as consumed.
	types, ok := b.typesOf(expr)
	if !ok {
		types = b.capTypes
	}
	leaves := b.conjuncts(expr, nil)

	for _, typ := range types {
		if caps, ok := b.caps.Events[typ]; ok {
			b.addType(r, typ, caps, leaves)
		}
		for _, dep := range b.caps.DependsOn[typ] {
			b.acceptAllScopes(dep, r)
		}
	}
}

// addType registers the rule with every scope of the event type it
// may consume events from.
func (b *builder) addType(r *Rule, typ event.Type, caps EventCaps, leaves []*ast.BinaryExpr) {
	for selector, keys := range caps.Keys {
		s := Scope{Type: typ, Selector: selector}
		switch b.selection(caps.Selector, selector, leaves) {
		case selectsNone:
			// the rule can't consume the events of this scope, so
			// it has no say on whether they are discarded
		case selectsSome:
			// the rule may consume the events of this scope, but the
			// selector isn't pinned to it, so its predicates can't be trusted
			b.acceptAll(s, r)
		case selectsExactly:
			b.add(s, b.approver(leaves, keys), r)
		}
	}
}

// selection tells how a rule relates to a scope.
type selection uint8

const (
	// selectsNone means the rule can't consume the events of the scope.
	selectsNone selection = iota
	// selectsSome means the rule may consume the events of the scope.
	selectsSome
	// selectsExactly means the rule pins the selector to the value of the scope.
	selectsExactly
)

// selection determines how the necessary comparisons on the selector attribute
// relate to the selector value of the scope. Only the = and ieq operators pin
// the selector, so file.operation in ('OPEN', 'CREATE') merely selects some.
// The types without a selector have a single scope that every rule pins.
func (b *builder) selection(selector Key, value string, leaves []*ast.BinaryExpr) selection {
	if selector.isZero() {
		return selectsExactly
	}
	sel := selectsSome
	for _, l := range leaves {
		f, ok := l.LHS.(*ast.FieldLiteral)
		if !ok || keyOf(f) != selector {
			continue
		}
		vals, ok := b.literalValues(l.RHS)
		if !ok {
			continue
		}
		m, ok := NewMatcher(l.Op, vals)
		if !ok {
			continue
		}
		if !m.Match(value) {
			return selectsNone
		}
		if l.Op == lexer.Eq || l.Op == lexer.IEq {
			sel = selectsExactly
		}
	}
	return sel
}

// approver turns the necessary comparisons that the event
// source can resolve into matchers.
func (b *builder) approver(leaves []*ast.BinaryExpr, keys []Key) Approver {
	var ap Approver
	for _, l := range leaves {
		f, ok := l.LHS.(*ast.FieldLiteral)
		if !ok {
			continue
		}
		key := keyOf(f)
		if !slices.Contains(keys, key) {
			continue
		}
		// vals, ok := b.literalValues(l.RHS)
		// if !ok {
		// 	continue
		// }
		// m, ok := NewMatcher(l.Op, vals)
		// if !ok {
		// 	continue
		// }
		//ap.Matchers = append(ap.Matchers, FieldMatcher{Key: key, Matcher: m, cost: opCost(l.Op)})
	}
	slices.SortStableFunc(ap.Matchers, func(x, y FieldMatcher) int { return cmp.Compare(x.cost, y.cost) })
	return ap
}

// exprs returns the expressions of the rule that consume events independently.
func (b *builder) exprs(r *Rule) []ast.Expr {
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
// Any node other than the comparisons, AND and parentheses (a negation
// included) is skipped along with everything below it.
func (b *builder) conjuncts(e ast.Expr, out []*ast.BinaryExpr) []*ast.BinaryExpr {
	switch n := e.(type) {
	case *ast.ParenExpr:
		return b.conjuncts(n.Expr, out)
	case *ast.BinaryExpr:
		switch n.Op {
		case lexer.And:
			return b.conjuncts(n.RHS, b.conjuncts(n.LHS, out))
		case lexer.Or:
			return out
		}
		return append(out, n)
	}
	return out
}

// literalValues returns the operands of a comparison if the right-hand
// side is a string or a list of strings.
func (b *builder) literalValues(e ast.Expr) ([]string, bool) {
	switch v := e.(type) {
	case *ast.StringLiteral:
		return []string{v.Value}, true
	case *ast.ListLiteral:
		return v.Values, true
	}
	return nil, false
}
