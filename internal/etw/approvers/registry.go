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
	"expvar"

	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/key"
)

var (
	registryApproverApprovals  = expvar.NewInt("approver.registry.approvals")
	registryApproverRejections = expvar.NewInt("approver.registry.rejections")
)

// registry approver accepts or discards key access events
// as soon as they are offloaded from the session buffer.
type registry struct {
	approver
	kcbs map[uint64]string
}

func newRegistryApprover(r *config.RulesCompileResult) Approver {
	return &registry{
		approver: approver{
			r: r,
		},
		kcbs: make(map[uint64]string),
	}
}

func (r *registry) Approve(rec *etw.EventRecord) (*etw.EventRecord, bool) {
	if rec.Header.ProviderID != event.RegistryEventGUID {
		return rec, true
	}

	id := rec.Header.EventDescriptor.Opcode

	// keep the state of allocated key control blocks
	// to be able to derive the full registry path
	if id == event.RegKCBRundownID || id == event.RegCreateKCBID {
		r.kcbs[rec.ReadUint64(16)] = rec.ConsumeUTF16String(24)
		return rec, true
	}
	if id == event.RegDeleteKCBID {
		delete(r.kcbs, rec.ReadUint64(16))
		return rec, true
	}

	// accept all but key access events
	if id != event.RegOpenKeyID {
		return rec, true
	}

	// lookup KCB map to check if the event
	// KCB object address references a key
	// we can use to reconstruct the full
	// registry path
	kcb := rec.ReadUint64(16)
	path := rec.ConsumeUTF16String(24)
	if kcb != 0 {
		path = key.ConcatPaths(r.kcbs[kcb], path)
	}

	rootkey, subkey := key.Format(path)
	if rootkey != key.Invalid {
		root := rootkey.String()
		if subkey != "" {
			path = key.ConcatPaths(root, subkey)
		} else {
			path = root
		}
	}

	if r.approveKey(path) {
		registryApproverApprovals.Add(1)
		return rec, true
	}

	registryApproverRejections.Add(1)

	return rec, false
}
