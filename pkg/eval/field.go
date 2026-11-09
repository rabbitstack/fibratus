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

package eval

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// Field contains field meta attributes all accessors need to extract the value.
type Field struct {
	Name     fields.Field
	Value    string
	Arg      string
	BoundVar string
}

// Fields is the set of unique fields referenced by an expression.
type Fields struct {
	fields []Field
	keys   map[string]struct{}
}

// NewFields creates an empty set of fields.
func NewFields() Fields {
	return Fields{keys: make(map[string]struct{})}
}

// Add adds the fields to the set. Fields that are already in
// the set, as determined by the field name, argument and bound
// variable, are ignored.
func (f *Fields) Add(flds ...Field) {
	if f.keys == nil {
		f.keys = make(map[string]struct{})
	}
	for _, fld := range flds {
		// key := fld.String() + "|" + fld.BoundVar
		// if _, ok := f.keys[key]; ok {
		// 	continue
		// }
		// f.keys[key] = struct{}{}
		f.fields = append(f.fields, fld)
	}
}

// List returns all fields in the order they were added.
func (f Fields) List() []Field { return f.fields }

// ExtractToValuer extracts the field values from the event and puts them
// in the valuer. Bound fields are skipped, since their values originate
// from the events matched in the preceding sequence steps rather than from
// the current event.
func (f Fields) ExtractToValuer(event *event.Event, valuer *ValuerCache) {
	for _, field := range f.fields {
		if field.IsBound() {
			continue
		}
		valuer.Put(event, field)
	}
}

// IsBound determines if the field refers to the event matched by the sequence step.
func (f Field) IsBound() bool { return f.BoundVar != "" }

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

func (f *Field) Extract(event *event.Event) any {
	for _, accessor := range GetAccessors() {
		if !accessor.IsFieldAccessible(event) {
			continue
		}
		v, err := accessor.Get(*f, event)
		if err != nil {
			// if !errs.IsParamNotFound(err) {
			// 	accessorErrors.Add(err.Error(), 1)
			// }
			//return defaultAccessorValue(*f)
		}
		if v != nil {
			return v
		}
	}
	return defaultAccessorValue(*f)
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
