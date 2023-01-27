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

package kevent

// Batch contains a sequence of kernel events.
type Batch struct {
	Events []*Kevent
}

// NewBatch produces a new batch from the group of events.
func NewBatch(evts ...*Kevent) *Batch {
	return &Batch{Events: evts}
}

// Len returns the length of the batch.
func (b *Batch) Len() int64 { return int64(len(b.Events)) }

// Release releases all events from the batch and returns them to the pool.
func (b *Batch) Release() {
	for _, e := range b.Events {
		e.Release()
	}
}

// Publish executes the publish function for each event in the batch.
func (b *Batch) Publish(pub func(*Kevent) error) error {
	for _, e := range b.Events {
		if err := pub(e); err != nil {
			return err
		}
	}
	return nil
}

// MarshalJSON serializes the batch of events to JSON format.
func (b *Batch) MarshalJSON() []byte {
	buf := make([]byte, 0)
	buf = append(buf, '[')
	for i, kevt := range b.Events {
		writeMore := true
		if i == len(b.Events)-1 {
			writeMore = false
		}
		buf = append(buf, kevt.MarshalJSON()...)
		buf = append(buf, '\n')
		if writeMore {
			buf = append(buf, ',')
		}
	}
	buf = append(buf, ']')
	return buf
}
