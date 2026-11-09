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

	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
)

// Matcher decides if the attribute value satisfies a single predicate
// extracted from the rule condition. There is one implementation per
// family of operators, so approving the event is a plain pass over the
// matchers without switching on the operator.
type Matcher interface {
	// Match returns true if the value satisfies the predicate.
	Match(value string) bool
	// String returns the predicate in the rule condition syntax.
	String() string
}

// ExactMatcher implements the = and ieq operators.
type ExactMatcher struct {
	value string
	fold  bool
}

// Match compares the value with the operand. The comparison is
// case-insensitive only for the ieq operator.
func (m ExactMatcher) Match(value string) bool {
	if m.fold {
		return strings.EqualFold(value, m.value)
	}
	return value == m.value
}

func (m ExactMatcher) String() string {
	if m.fold {
		return "ieq '" + m.value + "'"
	}
	return "= '" + m.value + "'"
}

// MembershipMatcher implements the in and iin operators.
type MembershipMatcher struct {
	set  map[string]struct{}
	vals []string
	fold bool
}

func newMembershipMatcher(vals []string, fold bool) MembershipMatcher {
	m := MembershipMatcher{set: make(map[string]struct{}, len(vals)), vals: slices.Clone(vals), fold: fold}
	for _, v := range vals {
		if fold {
			v = strings.ToLower(v)
		}
		m.set[v] = struct{}{}
	}
	return m
}

// Match returns true if the value is a member of the set.
func (m MembershipMatcher) Match(value string) bool {
	if m.fold {
		value = strings.ToLower(value)
	}
	_, ok := m.set[value]
	return ok
}

func (m MembershipMatcher) String() string {
	op := "in"
	if m.fold {
		op = "iin"
	}
	return op + " ('" + strings.Join(m.vals, "', '") + "')"
}

// PrefixMatcher implements the istartswith operator.
type PrefixMatcher struct{ prefixes []string }

// Match returns true if the value starts with any prefix, ignoring the case.
func (m PrefixMatcher) Match(value string) bool {
	value = strings.ToLower(value)
	return slices.ContainsFunc(m.prefixes, func(p string) bool { return strings.HasPrefix(value, p) })
}

func (m PrefixMatcher) String() string {
	return "istartswith ('" + strings.Join(m.prefixes, "', '") + "')"
}

// SuffixMatcher implements the iendswith operator.
type SuffixMatcher struct{ suffixes []string }

// Match returns true if the value ends with any suffix, ignoring the case.
func (m SuffixMatcher) Match(value string) bool {
	value = strings.ToLower(value)
	return slices.ContainsFunc(m.suffixes, func(s string) bool { return strings.HasSuffix(value, s) })
}

func (m SuffixMatcher) String() string {
	return "iendswith ('" + strings.Join(m.suffixes, "', '") + "')"
}

// ContainsMatcher implements the icontains operator.
type ContainsMatcher struct{ substrs []string }

// Match returns true if the value contains any substring, ignoring the case.
func (m ContainsMatcher) Match(value string) bool {
	value = strings.ToLower(value)
	return slices.ContainsFunc(m.substrs, func(s string) bool { return strings.Contains(value, s) })
}

func (m ContainsMatcher) String() string {
	return "icontains ('" + strings.Join(m.substrs, "', '") + "')"
}

// PatternMatcher implements the imatches operator.
type PatternMatcher struct{ patterns []string }

// Match returns true if the value matches any wildcard pattern, ignoring the case.
func (m PatternMatcher) Match(value string) bool {
	return slices.ContainsFunc(m.patterns, func(p string) bool { return wildcard.Match(p, value, false) })
}

func (m PatternMatcher) String() string {
	return "imatches ('" + strings.Join(m.patterns, "', '") + "')"
}

func lower(vals []string) []string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = strings.ToLower(v)
	}
	return out
}

// NewMatcher creates the matcher for the comparison operator and its operands.
// The second return value is false if the operator can't be approved, e.g. the
// case-sensitive contains, or if there are no operands.
func NewMatcher(op lexer.Token, vals []string) (Matcher, bool) {
	if len(vals) == 0 {
		return nil, false
	}
	switch op {
	case lexer.Eq, lexer.IEq:
		if len(vals) != 1 {
			return nil, false
		}
		return ExactMatcher{value: vals[0], fold: op == lexer.IEq}, true
	case lexer.In, lexer.IIn:
		return newMembershipMatcher(vals, op == lexer.IIn), true
	case lexer.IStartswith:
		return PrefixMatcher{prefixes: lower(vals)}, true
	case lexer.IEndswith:
		return SuffixMatcher{suffixes: lower(vals)}, true
	case lexer.IContains:
		return ContainsMatcher{substrs: lower(vals)}, true
	case lexer.IMatches:
		return PatternMatcher{patterns: slices.Clone(vals)}, true
	}
	return nil, false
}
