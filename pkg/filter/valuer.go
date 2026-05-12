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
	"sync"

	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/filter/ql"
)

// ValuerCache caches extracted field values for a single event's lifetime.
type ValuerCache struct {
	slots  [fields.MaxFieldID]any
	valuer ql.MapValuer
}

var valuerCachePool = sync.Pool{
	New: func() any {
		return &ValuerCache{
			valuer: make(ql.MapValuer, 8), // pre-allocate buckets
		}
	},
}

func AcquireValuerCache() *ValuerCache {
	return valuerCachePool.Get().(*ValuerCache)
}

func (c *ValuerCache) Release() {
	c.slots = [fields.MaxFieldID]any{}
	clear(c.valuer)
	valuerCachePool.Put(c)
}

func (c *ValuerCache) populateValuer(f Field, extract func() any) {
	id := f.Name.ID()
	if id == -1 {
		// if the field doesn't allow fast id lookup
		// extract the value and cache inside valuer
		n := f.String()
		if _, ok := c.valuer[n]; !ok {
			c.valuer[n] = extract()
		}
		return
	}

	// field value is already cached, skip
	v := c.slots[id]
	if v != nil {
		return
	}

	// extract the value and cache
	v = extract()
	c.slots[id], c.valuer[f.String()] = v, v
}
