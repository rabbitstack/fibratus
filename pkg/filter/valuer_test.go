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

package filter

import (
	"testing"

	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/stretchr/testify/assert"
)

var dontCallValuerFunc = func() any { return "should-not-be-called" }
var extractValueFunc = func() any { return "explorer.exe" }

func TestValuerCacheHit(t *testing.T) {
	c := AcquireValuerCache()
	defer c.Release()

	calls := 0
	extract := func() any {
		calls++
		return "explorer.exe"
	}

	f := Field{Name: fields.PsName, Value: fields.PsName.String()}

	c.populateValuer(f, extract)
	c.populateValuer(f, extract)

	assert.Equal(t, "explorer.exe", c.valuer[f.String()])
	assert.Equal(t, 1, calls, "extract must be called exactly once on repeated access")
}

func TestValuerCacheMiss(t *testing.T) {
	c := AcquireValuerCache()
	defer c.Release()

	f := Field{Name: fields.PsName, Value: fields.PsName.String()}
	c.populateValuer(f, func() any { return "svchost.exe" })

	assert.Equal(t, "svchost.exe", c.valuer[f.String()])
}

func TestValuerCacheDistinctFields(t *testing.T) {
	c := AcquireValuerCache()
	defer c.Release()

	f := Field{Name: fields.PsName, Value: fields.PsName.String()}
	f1 := Field{Name: fields.FilePath, Value: fields.FilePath.String()}

	c.populateValuer(f, extractValueFunc)
	c.populateValuer(f1, func() any { return `C:\Windows\System32\cmd.exe` })

	// populate again to verify no overwrite
	c.populateValuer(f, dontCallValuerFunc)
	c.populateValuer(f1, dontCallValuerFunc)

	assert.Equal(t, "explorer.exe", c.valuer[f.String()])
	assert.Equal(t, `C:\Windows\System32\cmd.exe`, c.valuer[f1.String()])
}

func TestValuerCacheNilValue(t *testing.T) {
	c := AcquireValuerCache()
	defer c.Release()

	calls := 0
	c.populateValuer(Field{Name: fields.PsName, Value: fields.PsName.String()}, func() any {
		calls++
		return nil
	})

	// nil is not cached in slots (v != nil check), so extract will be called again
	c.populateValuer(Field{Name: fields.PsName, Value: fields.PsName.String()}, func() any {
		calls++
		return nil
	})

	assert.Equal(t, 2, calls, "nil values are not cached, extract is called on every invocation")
}

func TestValuerCacheReset(t *testing.T) {
	c := AcquireValuerCache()

	c.populateValuer(Field{Name: fields.PsName, Value: fields.PsName.String()}, extractValueFunc)
	c.Release()

	// simulate pool returning the same instance
	c2 := AcquireValuerCache()
	defer c2.Release()

	calls := 0
	c2.populateValuer(Field{Name: fields.PsName, Value: fields.PsName.String()}, func() any {
		calls++
		return "notepad.exe"
	})

	assert.Equal(t, "notepad.exe", c2.valuer[fields.PsName.String()])
	assert.Equal(t, 1, calls, "slot must be cleared after Release")
}

func TestValuerCacheExtractCalledOnceAcrossRules(t *testing.T) {
	c := AcquireValuerCache()
	defer c.Release()

	calls := 0
	extract := func() any {
		calls++
		return uint32(1234)
	}

	// simulate 20 rules all requesting the same field
	for range 20 {
		c.populateValuer(Field{Name: fields.PsPid, Value: fields.PsPid.String()}, extract)
	}

	assert.Equal(t, uint32(1234), c.valuer[fields.PsPid.String()])
	assert.Equal(t, 1, calls, "extract must be called once regardless of rule count")
}

func TestValuerCacheAllSlotsIndependent(t *testing.T) {
	c := AcquireValuerCache()
	defer c.Release()

	want := map[Field]any{
		{Name: fields.PsName, Value: fields.PsName.String()}:     "explorer.exe",
		{Name: fields.PsPid, Value: fields.PsPid.String()}:       uint32(4),
		{Name: fields.FilePath, Value: fields.FilePath.String()}: `C:\Windows\System32\cmd.exe`,
	}

	for f, v := range want {
		val := v
		c.populateValuer(f, func() any { return val })
	}

	for f, expected := range want {
		assert.Equal(t, expected, c.valuer[f.String()], "field %v", f)
	}
}

func TestValuerCachePoolReuse(t *testing.T) {
	for i := range 10 {
		c := AcquireValuerCache()

		calls := 0
		c.populateValuer(Field{Name: fields.PsName, Value: fields.PsName.String()}, func() any {
			calls++
			return i
		})

		assert.Equal(t, i, c.valuer[fields.PsName.String()])
		assert.Equal(t, 1, calls, "event %d: stale slot from previous cycle", i)

		c.Release()
	}
}

func TestValuerCacheFieldWithoutID(t *testing.T) {
	c := AcquireValuerCache()
	defer c.Release()

	// fields with id == -1 always call extract, no caching
	calls := 0
	extract := func() any {
		calls++
		return "value"
	}

	c.populateValuer(Field{Name: fields.HandleID, Value: fields.HandleID.String()}, extract)
	c.populateValuer(Field{Name: fields.HandleName, Value: fields.HandleName.String()}, extract)

	assert.Equal(t, 2, calls, "unknown fields (id == -1) must not be cached")

	c.populateValuer(Field{Name: fields.HandleID, Value: fields.HandleID.String()}, dontCallValuerFunc)
	c.populateValuer(Field{Name: fields.HandleName, Value: fields.HandleName.String()}, dontCallValuerFunc)

	// now the fields should be cached
	assert.Equal(t, "value", c.valuer[fields.HandleID.String()])
	assert.Equal(t, "value", c.valuer[fields.HandleName.String()])
}

func BenchmarkValuerCacheHit(b *testing.B) {
	c := AcquireValuerCache()
	defer c.Release()

	c.populateValuer(Field{Name: fields.PsName, Value: fields.PsName.String()}, extractValueFunc)

	b.ResetTimer()
	b.ReportAllocs()

	for range b.N {
		c.populateValuer(Field{Name: fields.PsName, Value: fields.PsName.String()}, dontCallValuerFunc)
	}
}

func BenchmarkValuerCacheMiss(b *testing.B) {
	b.ReportAllocs()

	for range b.N {
		c := AcquireValuerCache()
		c.populateValuer(Field{Name: fields.PsName, Value: fields.PsName.String()}, extractValueFunc)
		c.Release()
	}
}

func BenchmarkValuerCacheFullEvent(b *testing.B) {
	// simulates 20 rules each requesting 3 fields on every event
	fieldsUnderTest := []Field{
		{Name: fields.PsName, Value: fields.PsName.String()},
		{Name: fields.PsPid, Value: fields.PsPid.String()},
		{Name: fields.FilePath, Value: fields.FilePath.String()},
	}

	b.ReportAllocs()

	for range b.N {
		c := AcquireValuerCache()
		for range 20 {
			for _, f := range fieldsUnderTest {
				field := f
				c.populateValuer(field, func() any { return "value" })
			}
		}
		c.Release()
	}
}
