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

	"github.com/rabbitstack/fibratus/internal/etw/processors"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	devmapper "github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"golang.org/x/sys/windows"
)

var (
	fsApproverApprovals  = expvar.NewInt("approver.fs.approvals")
	fsApproverRejections = expvar.NewInt("approver.fs.rejections")
)

// irp acts as a scratch area for the pending IRP request
// that is used as a signal to promote the file operation.
// The memory buffer backing the event record must outlive
// event processors scope.
type irp struct {
	rec   *etw.EventRecord
	buf   []byte                     // keeps the data buffer alive
	items *etw.FileExtendedDataItems // keeps the extended data items alive
}

// fs is the file system approver that accepts or discards
// file events as soon as they are pulled from the session
// buffers.
type fs struct {
	approver

	irps map[uint64]irp

	processors *processors.Chain
	approvers  []func(string) bool
}

func newFSApprover(r *config.RulesCompileResult, processors *processors.Chain) Approver {
	fs := &fs{
		approver: approver{
			r: r,
		},
		approvers:  make([]func(string) bool, 0),
		processors: processors,
		irps:       make(map[uint64]irp),
	}

	if r != nil && len(r.Approvers.Paths) > 0 {
		fs.approvers = append(fs.approvers, fs.approvePath)
	}
	if r != nil && len(r.Approvers.Extensions) > 0 {
		fs.approvers = append(fs.approvers, fs.approveExtension)
	}
	if r != nil && len(r.Approvers.Bases) > 0 {
		fs.approvers = append(fs.approvers, fs.approveBasename)
	}

	return fs
}

func (f *fs) Approve(r *etw.EventRecord) (*etw.EventRecord, bool) {
	if r.Header.ProviderID != event.FileEventGUID {
		return r, true
	}

	// enqueue in flight CreateFile event
	if r.Header.EventDescriptor.Opcode == event.CreateFileID {
		rec, buf := r.Copy()
		f.irps[r.ReadUint64(0)] = irp{rec: rec, buf: buf}
		return r, false
	}

	if r.Header.EventDescriptor.Opcode == event.FileOpEndID {
		disposition := r.ReadUint64(8)

		// the file operation finalization event arrived but not
		// for our previously queued CreateFile event as the extra
		// file information doesn't match any of the known file
		// dispositions flags. We can safely drop the event
		if disposition > windows.FILE_MAXIMUM_DISPOSITION {
			return r, false
		}

		i := r.ReadUint64(0)
		irp, ok := f.irps[i]
		if !ok {
			return r, false
		}

		rec := irp.rec
		status := r.ReadUint32(16)
		// if the I/O status is different than file open
		// or the rules compilation result is not present
		// we'll allow events flow downstream processors
		if f.r == nil || disposition != windows.FILE_OPEN {
			irp.items = etw.AppendEventHeaderFileExtendedDataItems(rec, disposition, status)
			f.irps[i] = irp
			return rec, true
		}

		// evaluate against available approvers
		var approved bool
		path := devmapper.GetDevMapper().Convert(rec.ConsumeUTF16String(32))
		for _, approver := range f.approvers {
			if approver(path) {
				approved = true
				break
			}
		}
		if !approved {
			// the event is rejected by approvers. Make sure to
			// evict the enqueded StackWalk event produced by the
			// CreateFile operation
			delete(f.irps, i)
			fsApproverRejections.Add(1)
			stackID := uint64(rec.Header.ProcessID + rec.Header.ThreadID)
			if f.processors != nil {
				f.processors.DequeueStackwalk(stackID)
			}
			return rec, false
		}

		fsApproverApprovals.Add(1)
		irp.items = etw.AppendEventHeaderFileExtendedDataItems(rec, disposition, status)
		f.irps[i] = irp
		return rec, true
	}

	return r, true
}

func (f *fs) cleanup(r *etw.EventRecord) {
	if r.Header.ProviderID == event.FileEventGUID && r.Header.EventDescriptor.Opcode == event.CreateFileID {
		i := r.ReadUint64(0)
		delete(f.irps, i)
	}
}
