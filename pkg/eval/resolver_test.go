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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestResolverIsMemoizedPerEvaluation(t *testing.T) {
	var calls int
	r := NewResolver("test", func(k string) int {
		calls++
		return len(k)
	})

	ctx := AcquireEvalCtx()
	assert.Equal(t, 3, r.Of(ctx, "abc"))
	assert.Equal(t, 3, r.Of(ctx, "abc"))
	assert.Equal(t, 1, calls, "the same key is resolved once")

	assert.Equal(t, 2, r.Of(ctx, "ab"))
	assert.Equal(t, 2, calls, "a different key is resolved on its own")

	// another resolver doesn't share the result, even for the same key
	other := NewResolver("other", func(k string) int { calls++; return -1 })
	assert.Equal(t, -1, other.Of(ctx, "abc"))
	assert.Equal(t, 3, calls)

	// the next event starts from scratch, but the context is reused
	ctx.Release()
	ctx = AcquireEvalCtx()
	defer ctx.Release()
	assert.Equal(t, 3, r.Of(ctx, "abc"))
	assert.Equal(t, 4, calls)
}

func TestNilResolverResolvesToZeroValue(t *testing.T) {
	var r *Resolver[string, int]
	ctx := AcquireEvalCtx()
	defer ctx.Release()
	assert.Zero(t, r.Of(ctx, "abc"))
	assert.Zero(t, NewResolver[string, int]("empty", nil).Of(ctx, "abc"))
}
