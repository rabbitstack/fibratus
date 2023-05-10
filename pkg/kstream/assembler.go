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

package kstream

import (
	"github.com/golang/groupcache/lru"
	"github.com/rabbitstack/fibratus/pkg/kevent"
)

// BacklogQueueSize the max size of the backlog queue
const BacklogQueueSize = 800

// backlog acts as LRU store for delayed events.
type backlog struct {
	q *lru.Cache
}

func newBacklog(size int) *backlog {
	return &backlog{q: lru.New(size)}
}

func (b *backlog) put(evt *kevent.Kevent) {
	if b.q.Len() > BacklogQueueSize {
		b.q.RemoveOldest()
	}
	b.q.Add(evt.DelayComparator(), evt)
}

func (b *backlog) pop(evt *kevent.Kevent) *kevent.Kevent {
	key := evt.DelayComparator()
	if key == nil {
		return nil
	}
	ev, ok := b.q.Get(key)
	if !ok {
		return nil
	}
	b.q.Remove(key)
	return ev.(*kevent.Kevent)
}

// EventAssembler assembles the event parameters from the state
// of some other event. It usually keeps the LRU store of events
// marked with delayed flag. The event contains the comparator key
// in its metadata.
type EventAssembler struct {
	kevts   chan *kevent.Kevent
	backlog *backlog // stores delayed events
}

// NewEventAssembler constructs a new event assembler.
func NewEventAssembler(kevts chan *kevent.Kevent) *EventAssembler {
	return &EventAssembler{kevts: kevts, backlog: newBacklog(BacklogQueueSize)}
}

func (a *EventAssembler) Assemble(e *kevent.Kevent) bool {
	// put delayed event in backlog
	if e.Delayed {
		a.backlog.put(e)
		return false
	}
	// lookup backlog for delayed event
	ev := a.backlog.pop(e)
	if ev != nil {
		ev.CopyFields(e)
		a.kevts <- ev
	}
	return true
}
