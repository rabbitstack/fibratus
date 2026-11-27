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
	"sync"

	"github.com/rabbitstack/fibratus/pkg/event"
)

// EvalCtx is the per-event evaluation context. It holds the field values
// extracted from the event, so they are extracted at most once even though
// many rules of the same bucket reference them. It is pooled, reset between
// events and shared by every rule evaluated against the event. It keeps
// feeding the compiled expression.
type EvalCtx struct {
	// Evt is the event the context is evaluated against. The typed
	// evaluators read the event from here.
	Evt *event.Event

	// Values are the values the expression reads, by their key. The key of an
	// extracted field is its string form. The values the sequence binds from the
	// preceding steps, and the variables of the foreach function, are keyed by the
	// variable as written in the expression, e.g. $e1.ps.name or $mod.path.
	Values map[string]any

	// Resolvers are the resolvers of the program that evaluates the event.
	Resolvers *Resolvers

	// peOpts selects the PE directories the program needs. They are derived
	// from the fields and the segments of the expression, and tell the PE
	// resolver what to parse.
	peOpts uint32

	// memo holds the results of the resolvers and the iterators for the
	// event, so they are computed at most once.
	memo map[memoKey]any
}

var evalCtxPool = sync.Pool{
	New: func() any {
		return &EvalCtx{
			Values: make(map[string]any),
		}
	},
}

func AcquireEvalCtx() *EvalCtx {
	return evalCtxPool.Get().(*EvalCtx)
}

func (c *EvalCtx) Release() {
	c.Evt = nil
	c.Resolvers = nil
	c.peOpts = 0
	clear(c.memo)
	clear(c.Values)
	evalCtxPool.Put(c)
}

// put extracts the field value from the context's event unless the context
// already has it. The value is keyed by the string form of the field, so every
// rule of the bucket that references the field shares one extraction.
func (c *EvalCtx) put(f *boundField, x *extractor) {
	if _, ok := c.Values[f.key]; !ok {
		c.Values[f.key] = x.extract(f.Field, f.eval, c)
	}
}
