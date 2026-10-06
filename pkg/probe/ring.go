/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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

package probe

import (
	"errors"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/smarty/go-disruptor"
)

const (
	ringCapacity = 1 << 16
	ringMask     = ringCapacity - 1
)

var ErrInsufficentRingSlots = errors.New("ring: insufficent slots")

// ringCommit attempts to reserve a single slot. If the
// slot is available, the event is written and commited
// to it. Otherwise, ErrInsufficentRingSlots error is returned.
func (p *Probe) ringCommit(evt *event.Event) error {
	seq := p.disruptor.TryReserve(1)
	if seq == disruptor.ErrCapacityUnavailable {
		return ErrInsufficentRingSlots
	}

	p.ring[seq&ringMask] = evt

	p.disruptor.Commit(seq, seq)

	return nil
}
