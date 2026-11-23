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

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// Field contains field meta attributes all accessors need to extract the value.
type Field struct {
	Name  fields.Field
	Value string
	Arg   string
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
	field := Field{Name: name, Value: val, Arg: arg}
	*fields = append(*fields, field)

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

// InterpolateFields replaces all occurrences of field modifiers in the given string
// with values extracted from the event. Field modifiers may contain a leading ordinal
// which refers to the event in particular sequence stage. Otherwise, the modifier is
// a well-known field name prepended with the `%` symbol.
func InterpolateFields(s string, evts []*event.Event) string {
	var fieldsReplRegexp = regexp.MustCompile(`%([1-9]?)\.?([a-z0-9A-Z\[\]._]+)`)
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
			var val any
			for _, accessor := range GetAccessors() {
				name, arg := split(m[2])
				f := Field{Value: m[2], Name: fields.Field(name), Arg: arg}
				var err error
				val, err = accessor.Get(f, evt)
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
