//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

package event

type Queue struct {
	queue
}

// NewQueue constructs a new queue with the given channel size.
func NewQueue(size int, stackEnrichment bool, enqueueAlways bool) *Queue {
	return &Queue{
		queue: queue{
			q:               make(chan *Event, size),
			listeners:       make([]Listener, 0),
			stackEnrichment: stackEnrichment,
			enqueueAlways:   enqueueAlways,
		},
	}
}

// NewQueueWithChannel constructs a new queue with a custom channel.
func NewQueueWithChannel(ch chan *Event, stackEnrichment bool, enqueueAlways bool) *Queue {
	return &Queue{
		queue: queue{
			q:               ch,
			listeners:       make([]Listener, 0),
			stackEnrichment: stackEnrichment,
			enqueueAlways:   enqueueAlways,
		},
	}
}

func (q *Queue) Push(e *Event) error {
	return q.push(e)
}

func (q *Queue) Close() {}
