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

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/rules"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
)

var (
	procApproverApprovals  = expvar.NewInt("approver.proc.approvals")
	procApproverRejections = expvar.NewInt("approver.proc.rejections")
)

// proc approver is responsible for filtering out process
// and thread access events.
type proc struct {
	approver
	psnap ps.Snapshotter
}

func newProcApprover(psnap ps.Snapshotter, p rules.ApproversProvider) Approver {
	return &proc{
		approver: approver{
			provider: p,
		},
		psnap: psnap,
	}
}

func (p *proc) Approve(r *etw.EventRecord) (*etw.EventRecord, bool) {
	if r.Header.ProviderID != event.AuditAPIEventGUID {
		return r, true
	}

	id := r.Header.EventDescriptor.ID
	if id != event.OpenProcessID && id != event.OpenThreadID {
		return r, true
	}

	// allow remote thread opens
	pid := r.ReadUint32(0)
	if id == event.OpenThreadID && r.Header.ProcessID != pid {
		return r, true
	}

	// attempt to find the target process in
	// the snapshotter state and passs the
	// executable path to the approver. If
	// we can find the process in snapshot
	// or the executable path is not resolve,
	// the event is approved
	ok, ps := p.psnap.Find(pid)
	if !ok || ps == nil || ps.Exe == "" {
		return r, true
	}
	typ := event.OpenProcess
	if id == event.OpenThreadID {
		typ = event.OpenThread
	}
	if p.approveExe(typ, ps.Exe) {
		procApproverApprovals.Add(1)
		return r, true
	}

	procApproverRejections.Add(1)

	return r, false
}

// approveExe asks the rule approvers if the process or thread open is
// approved given the executable path of the target process.
func (p *proc) approveExe(typ event.Type, exe string) bool {
	return p.approve(typ, func(k rules.Key) (string, bool) {
		if k.Field == fields.EvtArg && k.Arg == params.Exe {
			return exe, true
		}
		return "", false
	})
}
