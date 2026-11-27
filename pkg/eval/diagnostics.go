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

package eval

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// FieldWarning is a problem with a field of the expression that is known when
// the rule is loaded, as opposed to when an event is evaluated.
type FieldWarning struct {
	Field fields.Field
	// Reason explains the problem, e.g. which event types the rule is scoped to
	Reason string
}

func (w FieldWarning) String() string { return fmt.Sprintf("%s %s", w.Field, w.Reason) }

// FieldWarnings returns the warnings about the fields the expression references:
//
//   - a field that has no value for any event type in the scope of the
//     expression, so the comparison on it only ever sees the default value. The
//     scope lists the event types, and the gate of the source of the field tells
//     which of them can serve it
//   - a field whose event source is disabled, so no event that carries it is
//     ever produced. The predicate tells whether the source is enabled, and a nil
//     one assumes every source is
//   - a field that no source ever served and always reads as the default value
//
// The fields of the bound variables aren't checked, since their events are
// the ones of the other steps of the sequence.
func (e *Program) FieldWarnings(enabled func(fields.Source) bool) []FieldWarning {
	var ws []FieldWarning
	for _, f := range e.fields {
		src := f.Name.Source()
		if !hasEvaluator(f.Name) {
			ws = append(ws, FieldWarning{f.Name, "isn't read from any source, so it always evaluates to the default value"})
			continue
		}
		if !e.scope.IsUnbounded() && !canOccur(src, e.scope) {
			ws = append(ws, FieldWarning{f.Name, fmt.Sprintf("is never available in the event types the rule is scoped to (%s), so it always evaluates to the default value", e.scope.names())})
			continue
		}
		if enabled != nil && !enabled(src) {
			ws = append(ws, FieldWarning{f.Name, fmt.Sprintf("is read from the %s event source which is disabled, so it always evaluates to the default value", src)})
		}
	}
	return ws
}

// canOccur reports whether any of the event types in the scope can carry
// values of the source, given the process state and the callstack are present.
func canOccur(src fields.Source, scope Scope) bool {
	return slices.ContainsFunc(scope, func(t event.Type) bool {
		return servesEvent(src, bestCaseEvent(t))
	})
}

// names returns the comma separated names of the event types of the scope.
func (s Scope) names() string {
	names := make([]string, len(s))
	for i, t := range s {
		names[i] = t.String()
	}
	return strings.Join(names, ", ")
}
