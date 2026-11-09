/*
 * Copyright 2020-present by Nedim Sabic Sabic
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

package approvers

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/rules"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
)

// Approver represents the contract that every approver must satisfy.
type Approver interface {
	// Approve receives a raw event recored. It may return
	// a new event record, and always returns a flag to
	// indicate if the event is approved or rejected.
	Approve(r *etw.EventRecord) (*etw.EventRecord, bool)
}

// Approvers is the registry for all known approvers.
type Approvers struct {
	approvers []Approver

	fs *fs
}

// New creates a new approvers set. The provider supplies the approvers
// derived from the rules. If it is nil, no event is rejected by the rules.
func New(psnap ps.Snapshotter, provider rules.ApproversProvider) Approvers {
	p := Approvers{
		approvers: make([]Approver, 0),
	}

	p.fs = newFSApprover(provider).(*fs)

	p.approvers = append(p.approvers, p.fs)
	if provider != nil {
		p.approvers = append(p.approvers, newRegistryApprover(provider))
		p.approvers = append(p.approvers, newProcApprover(psnap, provider))
	}

	return p
}

// Approve renders a verdict about the event record.
// It evalutes available approvers against the event
// and if it satisifes the main condition for rule
// assertion, this method returns true. Otherwise, it
// returns false and instructs the consumer to drop the
// event record.
func (p *Approvers) Approve(r *etw.EventRecord) (*etw.EventRecord, bool) {
	if len(p.approvers) == 0 {
		return r, true
	}

	rec := r
	for _, approver := range p.approvers {
		e, ok := approver.Approve(rec)
		if !ok {
			return rec, false
		}
		rec = e
	}

	return rec, true
}

// Cleanup housekeeps approvers state.
func (p *Approvers) Cleanup(r *etw.EventRecord) {
	p.fs.cleanup(r)
}

// approver contains the base logic any approver can consume. It reads
// the approvers from the provider each time the event is approved, so the
// approvers derived from the rules reloaded by the engine are used right away.
type approver struct {
	provider rules.ApproversProvider
}

// active determines if the rules provide approvers.
func (a *approver) active() bool { return a.provider != nil }

// approve asks the rule approvers if the event of the type is approved.
func (a *approver) approve(typ event.Type, value rules.ValueFunc) bool {
	if a.provider == nil {
		return true
	}
	return a.provider.Approvers().Approve(typ, value)
}
