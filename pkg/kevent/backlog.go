/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package kevent

import (
	"github.com/golang/groupcache/lru"
)

// BacklogCacheSize the max size of the backlog cache
const BacklogCacheSize = 800

// Backlog acts as LRU store for delayed events.
// It keeps the delayed event indexed by the sequence
// identifier which could be any event parameter, tag
// or other useful piece of data that can connect two
// events.
type Backlog struct {
	cache *lru.Cache
}

// NewBacklog constructs a new event backlog.
func NewBacklog() *Backlog {
	return &Backlog{cache: lru.New(BacklogCacheSize)}
}

func (b *Backlog) Put(evt *Kevent) {
	if b.cache.Len() > BacklogCacheSize {
		b.cache.RemoveOldest()
	}
	seqID := evt.SequenceID()
	if seqID != 0 {
		b.cache.Add(seqID, evt)
	}
}

func (b *Backlog) Pop(evt *Kevent) *Kevent {
	seqID := evt.SequenceID()
	if seqID == 0 {
		return nil
	}
	ev, ok := b.cache.Get(seqID)
	if !ok {
		return nil
	}
	b.cache.Remove(seqID)
	e := ev.(*Kevent)
	e.Delayed = false
	e.CopyFields(evt)
	return e
}

func (b *Backlog) Size() int {
	return b.cache.Len()
}
