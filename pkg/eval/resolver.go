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

// Resolver is a named source of values that are expensive to produce: a
// signature verification, the metadata of a file, a reverse DNS lookup or a
// PE parse. The resolvers are injected into the programs, so tests can replace
// them and count the calls. The result is memoized in the evaluation context,
// so the fields of the event that need the same resolution share it, no matter
// how many rules of the bucket read them.
type Resolver[K comparable, V any] struct {
	// Name identifies the resolver in the diagnostics.
	Name string
	// Resolve produces the value for the key.
	Resolve func(K) V
}

// NewResolver creates the named resolver.
func NewResolver[K comparable, V any](name string, resolve func(K) V) *Resolver[K, V] {
	return &Resolver[K, V]{Name: name, Resolve: resolve}
}

// memoKey identifies a memoized result: the resolver or the iterator
// that produced it and the key it was resolved for.
type memoKey struct {
	slot any
	key  any
}

// Of returns the value of the key, resolving it only the first time it
// is asked for during the evaluation of the event. A nil resolver resolves
// to the zero value.
func (r *Resolver[K, V]) Of(ctx *EvalCtx, key K) V {
	if r == nil || r.Resolve == nil {
		var zero V
		return zero
	}
	return memoized(ctx, r, key, func() V { return r.Resolve(key) })
}

// memoized returns the result stored in the context under the slot and the
// key, or computes it and stores it. The context is not safe for concurrent
// use, since the evaluation of an event is single threaded.
func memoized[V any](ctx *EvalCtx, slot, key any, compute func() V) V {
	k := memoKey{slot: slot, key: key}
	if v, ok := ctx.memo[k]; ok {
		return v.(V)
	}
	v := compute()
	if ctx.memo == nil {
		ctx.memo = make(map[memoKey]any)
	}
	ctx.memo[k] = v
	return v
}
