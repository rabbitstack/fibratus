/*
 * Copyright 2026 by Mostafa Moradian
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
	"slices"
	"strconv"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
)

// ApproverProvider is an optional filter capability that exposes a
// conservative, kernel-safe extraction of positive predicates. Filters
// that do not implement it are treated as unextractable, which forces
// default-allow for every event type they could match.
type ApproverProvider interface {
	ApproverExtraction() Extraction
}

// Extraction is the conservative predicate set taken from one compiled
// filter. Unsupported is set when the AST contains a shape that cannot
// be proven as a superset of matches (OR, NOT, inequality, regex, range,
// function, bound field, or sequence).
type Extraction struct {
	Unsupported bool
	Types       []event.Type
	TypesScoped bool
	PIDs        []uint64
	FileExact   []string
	FilePrefix  []string
	Ports       []uint16
}

// TypePolicy is the in-kernel prefilter for one event type. DefaultAllow
// means userspace must see every event of that type. Otherwise an event
// must satisfy every required field, matching the union of allowed values.
type TypePolicy struct {
	DefaultAllow    bool
	RequirePID      bool
	RequireFilename bool
	RequirePort     bool
	PIDs            []uint64
	FileExact       []string
	FilePrefix      []string
	Ports           []uint16
}

// ApproverPlan is a platform-neutral description of per-type prefilters.
// It is derived from compiled filters and is not stored on RulesCompileResult,
// which remains a usage summary.
type ApproverPlan struct {
	policies map[event.Type]TypePolicy
}

// Sample is the subset of event fields the in-kernel approver can observe.
type Sample struct {
	Type      event.Type
	PID       uint64
	Filename  string
	Port      uint16
	Truncated bool
}

// AllowAllPlan returns a plan that never drops events.
func AllowAllPlan() *ApproverPlan {
	return &ApproverPlan{policies: map[event.Type]TypePolicy{}}
}

// PlanFromFilter builds a plan from a single compiled filter, typically the CLI
// expression supplied through SetFilter.
func PlanFromFilter(f Filter) *ApproverPlan {
	if f == nil {
		return AllowAllPlan()
	}
	return BuildApproverPlan([]Filter{f})
}

// BuildApproverPlan unions extractable predicates across filters. A type is
// default-allow when any applicable filter is unextractable, when no filter
// applies, or when the applicable filters do not share a required field.
func BuildApproverPlan(filters []Filter) *ApproverPlan {
	plan := AllowAllPlan()
	if len(filters) == 0 {
		return plan
	}

	byType := make(map[event.Type][]Extraction)
	blocked := make(map[event.Type]bool)

	for _, f := range filters {
		provider, ok := f.(ApproverProvider)
		if !ok {
			for _, typ := range event.AllTypes() {
				blocked[typ] = true
			}
			continue
		}
		ex := provider.ApproverExtraction()
		types := scopedTypes(ex)
		if ex.Unsupported {
			for _, typ := range types {
				blocked[typ] = true
			}
			continue
		}
		for _, typ := range types {
			byType[typ] = append(byType[typ], ex)
		}
	}

	for _, typ := range event.AllTypes() {
		if blocked[typ] || len(byType[typ]) == 0 {
			plan.policies[typ] = TypePolicy{DefaultAllow: true}
			continue
		}
		plan.policies[typ] = policyFromClauses(byType[typ])
	}
	return plan
}

// Union combines plans by intersecting required fields and unioning their
// allowed values. Any default-allow policy wins, which is the safe direction.
func Union(plans ...*ApproverPlan) *ApproverPlan {
	var out *ApproverPlan
	for _, p := range plans {
		if p == nil {
			continue
		}
		if out == nil {
			out = clonePlan(p)
			continue
		}
		for _, typ := range event.AllTypes() {
			out.policies[typ] = unionPolicy(out.Policy(typ), p.Policy(typ))
		}
	}
	if out == nil {
		return AllowAllPlan()
	}
	return out
}

// Policy returns the prefilter for an event type. Missing types default-allow.
func (p *ApproverPlan) Policy(t event.Type) TypePolicy {
	if p == nil || p.policies == nil {
		return TypePolicy{DefaultAllow: true}
	}
	pol, ok := p.policies[t]
	if !ok {
		return TypePolicy{DefaultAllow: true}
	}
	return pol
}

// Allows reports whether the kernel prefilter would keep the sample. A true
// userspace match must always produce true here; false positives are allowed.
func (p *ApproverPlan) Allows(s Sample) bool {
	if AlwaysAllowed(s.Type) {
		return true
	}
	pol := p.Policy(s.Type)
	if pol.DefaultAllow {
		return true
	}
	if pol.RequirePID && !slices.Contains(pol.PIDs, s.PID) {
		return false
	}
	if pol.RequireFilename && !s.Truncated && !matchFilename(pol, s.Filename) {
		return false
	}
	if pol.RequirePort && !slices.Contains(pol.Ports, s.Port) {
		return false
	}
	return true
}

var _ ApproverProvider = (*filter)(nil)

func (f *filter) ApproverExtraction() Extraction {
	if f.seq != nil {
		// Sequence matching is stateful: an early stage has to reach userspace
		// for a later one to ever fire, so no stage can be prefiltered. Scope
		// the block to the event names and categories in the filter's string
		// fields, which is the same set rules.Engine indexes the sequence by,
		// so the approver and the engine cannot disagree about which types can
		// reach the rule.
		ex := Extraction{Unsupported: true, TypesScoped: true}
		ex.Types = typesFromStringFields(f.stringFields)
		return ex
	}
	return extractFromExpr(f.expr)
}

// typesFromStringFields mirrors the event name and category indexing performed
// by rules.Engine.Compile.
func typesFromStringFields(stringFields map[fields.Field][]string) []event.Type {
	var types []event.Type
	for _, name := range stringFields[fields.EvtName] {
		typ, ok := event.ParseType(name)
		if !ok {
			continue
		}
		types = append(types, typ)
	}
	for _, name := range stringFields[fields.EvtCategory] {
		cat, ok := event.ParseCategory(name)
		if !ok {
			continue
		}
		for _, typ := range event.AllTypes() {
			info := event.GetTypeInfo(typ)
			if info.Category == cat {
				types = append(types, typ)
			}
		}
	}
	return uniqueTypes(types)
}

func extractFromExpr(root ql.Node) Extraction {
	var ex Extraction
	if root == nil {
		ex.Unsupported = true
		return ex
	}
	ql.WalkFunc(root, func(n ql.Node) {
		switch node := n.(type) {
		case *ql.NotExpr, *ql.Function:
			ex.Unsupported = true
		case *ql.BinaryExpr:
			extractBinary(&ex, node)
		}
	})
	ex.Types = uniqueTypes(ex.Types)
	ex.PIDs = uniqueUint64(ex.PIDs)
	ex.FileExact = uniqueStrings(ex.FileExact)
	ex.FilePrefix = uniqueStrings(ex.FilePrefix)
	ex.Ports = uniqueUint16(ex.Ports)
	return ex
}

func extractBinary(ex *Extraction, expr *ql.BinaryExpr) {
	switch expr.Op {
	case ql.And:
		return
	case ql.Or:
		ex.Unsupported = true
		return
	}

	lhs, ok := expr.LHS.(*ql.FieldLiteral)
	if !ok {
		ex.Unsupported = true
		return
	}
	if _, ok := expr.RHS.(*ql.BoundFieldLiteral); ok {
		ex.Unsupported = true
		return
	}

	switch lhs.Field {
	case fields.EvtName:
		extractEventNames(ex, expr)
	case fields.EvtCategory:
		extractCategories(ex, expr)
	case fields.EvtPID, fields.PsPid:
		extractPIDs(ex, expr)
	case fields.FilePath:
		extractFilenames(ex, expr)
	case fields.NetDport:
		extractPorts(ex, expr)
	default:
		// ps.name is deliberately absent. The only process name the kernel can
		// read cheaply is the live task comm, while ps.name is snapshot state
		// captured at execve. They diverge under prctl(PR_SET_NAME) and when
		// the snapshot falls back to an executable basename longer than comm's
		// 16 bytes, either of which would drop a matching event.
		ex.Unsupported = true
	}
}

func extractEventNames(ex *Extraction, expr *ql.BinaryExpr) {
	if expr.Op != ql.Eq && expr.Op != ql.In {
		ex.Unsupported = true
		return
	}
	names, ok := rhsStrings(expr.RHS)
	if !ok {
		ex.Unsupported = true
		return
	}
	ex.TypesScoped = true
	for _, name := range names {
		typ, ok := event.ParseType(name)
		if !ok {
			continue
		}
		ex.Types = append(ex.Types, typ)
	}
}

func extractCategories(ex *Extraction, expr *ql.BinaryExpr) {
	if expr.Op != ql.Eq && expr.Op != ql.In {
		ex.Unsupported = true
		return
	}
	names, ok := rhsStrings(expr.RHS)
	if !ok {
		ex.Unsupported = true
		return
	}
	ex.TypesScoped = true
	for _, name := range names {
		cat, ok := event.ParseCategory(name)
		if !ok {
			continue
		}
		for _, typ := range event.AllTypes() {
			info := event.GetTypeInfo(typ)
			if info.Category == cat {
				ex.Types = append(ex.Types, typ)
			}
		}
	}
}

func extractPIDs(ex *Extraction, expr *ql.BinaryExpr) {
	if expr.Op != ql.Eq && expr.Op != ql.In {
		ex.Unsupported = true
		return
	}
	nums, ok := rhsUint64(expr.RHS)
	if !ok {
		ex.Unsupported = true
		return
	}
	ex.PIDs = append(ex.PIDs, nums...)
}

func extractFilenames(ex *Extraction, expr *ql.BinaryExpr) {
	switch expr.Op {
	case ql.Eq, ql.In:
		names, ok := rhsStrings(expr.RHS)
		if !ok {
			ex.Unsupported = true
			return
		}
		ex.FileExact = append(ex.FileExact, names...)
	case ql.Startswith:
		names, ok := rhsStrings(expr.RHS)
		if !ok {
			ex.Unsupported = true
			return
		}
		for _, name := range names {
			if name == "" {
				continue
			}
			ex.FilePrefix = append(ex.FilePrefix, name)
		}
	case ql.Matches:
		names, ok := rhsStrings(expr.RHS)
		if !ok {
			ex.Unsupported = true
			return
		}
		for _, name := range names {
			literal, prefix, ok := globAsPrefix(name)
			if !ok {
				ex.Unsupported = true
				return
			}
			switch {
			case literal != "":
				ex.FileExact = append(ex.FileExact, literal)
			case prefix != "":
				ex.FilePrefix = append(ex.FilePrefix, prefix)
			}
		}
	default:
		// imatches stays out: case folding the path in the kernel would have to
		// agree with unicode.ToLower on every rune userspace folds.
		ex.Unsupported = true
	}
}

func extractPorts(ex *Extraction, expr *ql.BinaryExpr) {
	if expr.Op != ql.Eq && expr.Op != ql.In {
		ex.Unsupported = true
		return
	}
	nums, ok := rhsUint64(expr.RHS)
	if !ok {
		ex.Unsupported = true
		return
	}
	for _, n := range nums {
		if n > 65535 {
			ex.Unsupported = true
			return
		}
		ex.Ports = append(ex.Ports, uint16(n))
	}
}

// scopedTypes resolves which event types an extraction speaks for. An
// extraction that names no event type at all covers every type, which is right
// for a CLI filter because the source evaluates it against every event. Rules
// are not in that position: rules.Engine discards a rule without an event name
// or category, so the compiler keeps unscoped rules out of the plan entirely
// rather than letting their predicates constrain anything here.
func scopedTypes(ex Extraction) []event.Type {
	if len(ex.Types) > 0 {
		return uniqueTypes(ex.Types)
	}
	if ex.TypesScoped {
		return nil
	}
	return event.AllTypes()
}

func policyFromClauses(clauses []Extraction) TypePolicy {
	reqPID, reqFile, reqPort := true, true, true
	for _, c := range clauses {
		if len(c.PIDs) == 0 {
			reqPID = false
		}
		if len(c.FileExact)+len(c.FilePrefix) == 0 {
			reqFile = false
		}
		if len(c.Ports) == 0 {
			reqPort = false
		}
	}
	if !reqPID && !reqFile && !reqPort {
		return TypePolicy{DefaultAllow: true}
	}
	pol := TypePolicy{
		RequirePID:      reqPID,
		RequireFilename: reqFile,
		RequirePort:     reqPort,
	}
	for _, c := range clauses {
		if reqPID {
			pol.PIDs = append(pol.PIDs, c.PIDs...)
		}
		if reqFile {
			pol.FileExact = append(pol.FileExact, c.FileExact...)
			pol.FilePrefix = append(pol.FilePrefix, c.FilePrefix...)
		}
		if reqPort {
			pol.Ports = append(pol.Ports, c.Ports...)
		}
	}
	pol.PIDs = uniqueUint64(pol.PIDs)
	pol.FileExact = uniqueStrings(pol.FileExact)
	pol.FilePrefix = uniqueStrings(pol.FilePrefix)
	pol.Ports = uniqueUint16(pol.Ports)
	return pol
}

func unionPolicy(a, b TypePolicy) TypePolicy {
	if a.DefaultAllow || b.DefaultAllow {
		return TypePolicy{DefaultAllow: true}
	}
	reqPID := a.RequirePID && b.RequirePID
	reqFile := a.RequireFilename && b.RequireFilename
	reqPort := a.RequirePort && b.RequirePort
	if !reqPID && !reqFile && !reqPort {
		return TypePolicy{DefaultAllow: true}
	}
	pol := TypePolicy{
		RequirePID:      reqPID,
		RequireFilename: reqFile,
		RequirePort:     reqPort,
	}
	if reqPID {
		pol.PIDs = uniqueUint64(append(append([]uint64{}, a.PIDs...), b.PIDs...))
	}
	if reqFile {
		pol.FileExact = uniqueStrings(append(append([]string{}, a.FileExact...), b.FileExact...))
		pol.FilePrefix = uniqueStrings(append(append([]string{}, a.FilePrefix...), b.FilePrefix...))
	}
	if reqPort {
		pol.Ports = uniqueUint16(append(append([]uint16{}, a.Ports...), b.Ports...))
	}
	return pol
}

func clonePlan(p *ApproverPlan) *ApproverPlan {
	out := AllowAllPlan()
	for typ, pol := range p.policies {
		out.policies[typ] = pol
	}
	return out
}

// globAsPrefix rewrites a matches pattern into the exact or prefix form the
// kernel can already evaluate. There is no in-kernel glob matcher because a
// backtracking one is not verifiable, so only patterns provably equivalent to
// one of those two forms are accepted:
//
//	/etc/passwd -> exact, no wildcard at all
//	/tmp/*      -> prefix, since '*' spans every remaining byte including '/'
//	*           -> vacuous, matches everything and constrains nothing
//
// A '*' anywhere but the end, or any '?', reports false and leaves the event
// type default-allow. Callers must pass the pattern through collapseStars so
// /tmp/** reaches here as /tmp/*.
func globAsPrefix(pattern string) (literal, prefix string, ok bool) {
	pattern = collapseStars(pattern)
	if strings.ContainsRune(pattern, '?') {
		return "", "", false
	}
	switch strings.Count(pattern, "*") {
	case 0:
		return pattern, "", true
	case 1:
		if !strings.HasSuffix(pattern, "*") {
			return "", "", false
		}
		return "", strings.TrimSuffix(pattern, "*"), true
	default:
		return "", "", false
	}
}

// collapseStars rewrites runs of '*' as a single '*'. The two are equivalent to
// matchCaseSensitive, which only ever remembers the most recent star position.
func collapseStars(pattern string) string {
	if !strings.Contains(pattern, "**") {
		return pattern
	}
	var b strings.Builder
	b.Grow(len(pattern))
	var prevStar bool
	for i := range len(pattern) {
		c := pattern[i]
		if c == '*' && prevStar {
			continue
		}
		prevStar = c == '*'
		b.WriteByte(c)
	}
	return b.String()
}

func matchFilename(pol TypePolicy, path string) bool {
	if slices.Contains(pol.FileExact, path) {
		return true
	}
	for _, prefix := range pol.FilePrefix {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func rhsStrings(n ql.Node) ([]string, bool) {
	switch v := n.(type) {
	case *ql.StringLiteral:
		return []string{v.Value}, true
	case *ql.ListLiteral:
		return v.Values, true
	}
	return nil, false
}

func rhsUint64(n ql.Node) ([]uint64, bool) {
	switch v := n.(type) {
	case *ql.IntegerLiteral:
		if v.Value < 0 {
			return nil, false
		}
		return []uint64{uint64(v.Value)}, true
	case *ql.UnsignedLiteral:
		return []uint64{v.Value}, true
	case *ql.StringLiteral:
		n, err := strconv.ParseUint(v.Value, 10, 64)
		if err != nil {
			return nil, false
		}
		return []uint64{n}, true
	case *ql.ListLiteral:
		out := make([]uint64, 0, len(v.Values))
		for _, s := range v.Values {
			n, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return nil, false
			}
			out = append(out, n)
		}
		return out, true
	}
	return nil, false
}

func uniqueTypes(in []event.Type) []event.Type {
	return unique(in, func(a, b event.Type) bool { return a == b })
}

func uniqueUint64(in []uint64) []uint64 {
	return unique(in, func(a, b uint64) bool { return a == b })
}

func uniqueUint16(in []uint16) []uint16 {
	return unique(in, func(a, b uint16) bool { return a == b })
}

func uniqueStrings(in []string) []string {
	return unique(in, func(a, b string) bool { return a == b })
}

func unique[T any](in []T, eq func(T, T) bool) []T {
	if len(in) == 0 {
		return nil
	}
	out := make([]T, 0, len(in))
	for _, v := range in {
		if slices.ContainsFunc(out, func(e T) bool { return eq(e, v) }) {
			continue
		}
		out = append(out, v)
	}
	return out
}
