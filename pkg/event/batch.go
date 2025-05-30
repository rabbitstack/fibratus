/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

// Batch contains a group of events.
type Batch struct {
	Events []*Event
}

// NewBatch produces a new batch from the group of events.
func NewBatch(evts ...*Event) *Batch {
	return &Batch{Events: evts}
}

// Len returns the length of the batch.
func (b *Batch) Len() int64 { return int64(len(b.Events)) }

// MarshalJSON serializes the batch of events to JSON format.
func (b *Batch) MarshalJSON() []byte {
	buf := make([]byte, 0)
	buf = append(buf, '[')
	for i, evt := range b.Events {
		writeMore := true
		if i == len(b.Events)-1 {
			writeMore = false
		}
		buf = append(buf, evt.MarshalJSON()...)
		buf = append(buf, '\n')
		if writeMore {
			buf = append(buf, ',')
		}
	}
	buf = append(buf, ']')
	return buf
}
