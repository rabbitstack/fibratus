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

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// ValuerCache caches extracted field values for a single event's lifetime.
type ValuerCache struct {
	Valuer ast.MapValuer
}

var valuerCachePool = sync.Pool{
	New: func() any {
		return &ValuerCache{
			Valuer: make(ast.MapValuer),
		}
	},
}

func AcquireValuerCache() *ValuerCache {
	return valuerCachePool.Get().(*ValuerCache)
}

func (c *ValuerCache) Release() {
	clear(c.Valuer)
	valuerCachePool.Put(c)
}

func (c *ValuerCache) populateValuer(f Field, event *event.Event) {
	n := f.String()
	if _, ok := c.Valuer[n]; !ok {
		c.Valuer[n] = f.Extract(event)
	}
}
