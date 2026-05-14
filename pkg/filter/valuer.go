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

	"github.com/rabbitstack/fibratus/pkg/filter/ql"
)

// ValuerCache caches extracted field values for a single event's lifetime.
type ValuerCache struct {
	valuer ql.MapValuer
}

var valuerCachePool = sync.Pool{
	New: func() any {
		return &ValuerCache{
			valuer: make(ql.MapValuer),
		}
	},
}

func AcquireValuerCache() *ValuerCache {
	return valuerCachePool.Get().(*ValuerCache)
}

func (c *ValuerCache) Release() {
	clear(c.valuer)
	valuerCachePool.Put(c)
}

func (c *ValuerCache) populateValuer(f Field, extract func() any) {
	n := f.String()
	if _, ok := c.valuer[n]; !ok {
		c.valuer[n] = extract()
	}
}
