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
	"expvar"
	"sync"

	errs "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// accessorErrors counts the unexpected errors accessors return, by message.
var accessorErrors = expvar.NewMap("eval.accessor.errors")

// FieldsConfigurer is implemented by accessors whose behavior depends on the
// fields referenced by the expression. For example, the PE accessor enables
// only the parser options the fields in the rule need. Such an accessor holds
// per-expression state, so every Extractor gets a private instance of it.
type FieldsConfigurer interface {
	SetFields(fields []Field)
}

// SegmentsConfigurer is the same as FieldsConfigurer, but for accessors
// that depend on the segments referenced by the expression.
type SegmentsConfigurer interface {
	SetSegments(segments []Segment)
}

// sharedAccessors holds the accessors that don't depend on the expression.
// They are created once and shared by all extractors, so they must be safe
// for concurrent use.
var sharedAccessors = sync.OnceValue(GetAccessors)

// newAccessors returns the accessor chain for an expression that references
// the given fields and segments. Stateless accessors are shared, while the
// ones that implement FieldsConfigurer or SegmentsConfigurer are private
// instances configured for this expression. The chain keeps the order
// of GetAccessors.
func newAccessors(flds []Field, segs []Segment) []Accessor {
	//shared := sharedAccessors()
	accessors := GetAccessors()

	// 	for i, acc := range accessors {
	// 		fc, hasFields := acc.(FieldsConfigurer)
	// 		sc, hasSegments := acc.(SegmentsConfigurer)
	// 		if !hasFields && !hasSegments {
	// 			accessors[i] = shared[i]
	// 			continue
	// 		}
	// 		if hasFields {
	// 			fc.SetFields(flds)
	// 		}
	// 		if hasSegments {
	// 			sc.SetSegments(segs)
	// 		}
	// 	}
	// 	return accessors
	return accessors
}

// Extractor extracts field values from events using accessors tailored to
// the fields and segments of a single expression.
type Extractor struct {
	// unbound are the fields whose values come from the evaluated event.
	// Bound fields are skipped, since their values originate from the events
	// matched in the preceding sequence steps.
	unbound   []Field
	accessors []Accessor
}

// NewExtractor creates the extractor for an expression that references
// the given fields and segments.
func NewExtractor(flds []Field, segs []Segment) *Extractor {
	x := &Extractor{accessors: newAccessors(flds, segs)}
	for _, f := range flds {
		if !f.IsBound() {
			x.unbound = append(x.unbound, f)
		}
	}
	return x
}

// ExtractToValuer puts the values of all the unbound fields from the
// event into the valuer, so they are available before the evaluation.
func (x *Extractor) ExtractToValuer(evt *event.Event, valuer *ValuerCache) {
	// for _, f := range x.unbound {
	// 	valuer.Put(evt, f, x)
	// }
}

// Extract returns the value of the field in the event. The accessors are
// tried in order and the first one that has a value wins. If none does, the
// default value for the field is returned.
func (x *Extractor) Extract(f Field, evt *event.Event) any {
	for _, acc := range x.accessors {
		if !acc.IsFieldAccessible(evt) {
			continue
		}
		v, err := acc.Get(f, evt)
		if err != nil {
			if !errs.IsParamNotFound(err) {
				accessorErrors.Add(err.Error(), 1)
			}
			continue
		}
		if v != nil {
			return v
		}
	}
	return defaultAccessorValue(f)
}
