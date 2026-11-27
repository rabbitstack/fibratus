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
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// Field contains field meta attributes the evaluators need to extract the value.
type Field struct {
	Name  fields.Field
	Value string
	Arg   string

	// n is the argument parsed as an integer. It is set by NewField if the
	// argument is a number, so the evaluators that index into a collection,
	// e.g. ps.ancestor[1], don't parse it again for every event.
	n    int
	hasN bool
}

// NewField creates the field. A numeric argument is parsed here, once, instead
// of in the evaluator for every event.
func NewField(name fields.Field, value, arg string) Field {
	f := Field{Name: name, Value: value, Arg: arg}
	if arg != "" {
		if n, err := strconv.Atoi(arg); err == nil {
			f.n, f.hasN = n, true
		}
	}
	return f
}

// IntArg returns the argument of the field as an integer. It is the value
// parsed by NewField when available. A field that wasn't made by NewField,
// or whose argument isn't a number, falls back to parsing the argument, so
// the error is the one strconv reports.
func (f Field) IntArg() (int, error) {
	if f.hasN {
		return f.n, nil
	}
	return strconv.Atoi(f.Arg)
}

func (f *Field) String() string {
	if f.Arg != "" {
		var b strings.Builder
		b.Grow(len(f.Value) + len(f.Arg) + 2)
		b.WriteString(f.Value)
		b.WriteByte('[')
		b.WriteString(f.Arg)
		b.WriteByte(']')
		return b.String()
	}
	return f.Value
}

// Fields is the set of unique fields referenced by an expression.
type Fields []Field

// Add add adds the field to the set. Fields that are already in
// the set, as determined by the field name and argument are ignored.
func (fields *Fields) Add(name fields.Field, val, arg string) {
	*fields = append(*fields, NewField(name, val, arg))

	slices.SortFunc(*fields, func(a, b Field) int {
		return cmp.Compare(a.String(), b.String())
	})

	*fields = slices.CompactFunc(*fields, func(a, b Field) bool {
		return a.String() == b.String()
	})
}

type Segment struct {
}

type Segments []Segment

// fieldsReplRegexp matches the field modifiers in the string to interpolate.
var fieldsReplRegexp = regexp.MustCompile(`%([1-9]?)\.?([a-z0-9A-Z\[\]._]+)`)

// defaultExtractor is the extractor that isn't tuned to any expression. It resolves the field modifiers when the caller doesn't
// own an evaluator.
var defaultExtractor = sync.OnceValue(func() *extractor { return newExtractor(nil, nil, nil) })

// InterpolateFields replaces all occurrences of field modifiers in the given string
// with values extracted from the event. Field modifiers may contain a leading ordinal
// which refers to the event in particular sequence stage. Otherwise, the modifier is
// a well-known field name prepended with the `%` symbol.
//
// The values are resolved through the evaluators with the default resolvers.
// Prefer Program.InterpolateFields when the rule's evaluator is at hand.
func InterpolateFields(s string, evts []*event.Event) string {
	return interpolateFields(s, evts, defaultExtractor())
}

// InterpolateFields replaces the field modifiers in the string with the
// values extracted from the events. See the package level InterpolateFields.
// The values are resolved through the extractor of the evaluator, so the
// resolvers are the ones the program was created with.
func (e *Program) InterpolateFields(s string, evts []*event.Event) string {
	if e == nil || e.extractor == nil {
		return InterpolateFields(s, evts)
	}
	return interpolateFields(s, evts, e.extractor)
}

func interpolateFields(s string, evts []*event.Event, x *extractor) string {
	matches := fieldsReplRegexp.FindAllStringSubmatch(s, -1)
	r := s
	if len(matches) == 0 {
		return s
	}

	split := func(s string) (string, string) {
		n, m := strings.Index(s, "["), strings.Index(s, "]")
		if n < 0 || m < 0 {
			return s, ""
		}
		if n > m {
			return s, ""
		}
		return s[0:n], s[n+1 : m]
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
			evt := evts[i-1]
			// extract field value from the event and replace in string
			name, arg := split(m[2])
			val := x.lookup(NewField(fields.Field(name), m[2], arg), evt)
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
