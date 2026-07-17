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
	"time"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	devmapper "github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/utf16"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	"github.com/zeebo/xxh3"
	"golang.org/x/sys/windows"
)

var (
	fsApproverApprovals  = expvar.NewInt("approver.fs.approvals")
	fsApproverRejections = expvar.NewInt("approver.fs.rejections")

	fsApproverCallstackMisses = expvar.NewInt("approver.fs.callstack.misses")
)

// irp acts as a scratch area for the pending IRP request
// that is used as a signal to promote the file operation.
// The memory buffer backing the event record must outlive
// event processors scope, along with the extended data items
// and the event callstack.
type irp struct {
	rec       *etw.EventRecord           // keeps the original even record
	items     *etw.FileExtendedDataItems // keeps the extended data items alive
	buf       []byte                     // keeps the data buffer alive
	callstack va.Callstack               // CreateFile stack return addresses
}

func (p *irp) storeExtendedDataItems(disposition uint64, status uint32) {
	p.items = etw.AppendEventHeaderFileExtendedDataItems(p.rec, disposition, status, p.callstack)
}

func (p *irp) storeCallstack(r *etw.EventRecord) {
	p.callstack = r.ReadCallstackInto(16, va.GetCallstack())
}

func (p *irp) releasePools() {
	p.rec.ReleasePool()
	if p.items != nil {
		p.items.ReleasePool()
	}
	if p.callstack != nil {
		p.callstack.ReleasePool()
	}
}

// fs is the file system approver that accepts or discards
// file events as soon as they are pulled from the session
// buffers.
type fs struct {
	approver

	irps map[uint64]irp

	approvers []func(string) bool

	pathLRUCache *expirable.LRU[uint64, string] // interned file paths
}

func hashFilePath(u []uint16) uint64 {
	b := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(u))), len(u))
	return xxh3.Hash(b)
}

func newFSApprover(r *config.RulesCompileResult) Approver {
	fs := &fs{
		approver: approver{
			r: r,
		},
		approvers:    make([]func(string) bool, 0),
		irps:         make(map[uint64]irp, 120),
		pathLRUCache: expirable.NewLRU[uint64, string](2500, nil, time.Minute*5),
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
	isStackwalk := r.Header.ProviderID == event.StackWalkEventGUID && r.Header.EventDescriptor.Opcode == event.StackWalkID
	if r.Header.ProviderID != event.FileEventGUID && !isStackwalk {
		return r, true
	}

	// clone and enqueue in flight CreateFile event
	if r.Header.EventDescriptor.Opcode == event.CreateFileID {
		i := r.ReadUint64(0)
		rec, buf := r.Clone()
		f.irps[i] = irp{rec: rec, buf: buf}
		return r, false
	}

	// associate the callstack return addresses to the CreateFile event
	// obtained from the StackWalk event by event timestamp correlation
	if isStackwalk {
		ts := r.ReadUint64(0)
		for i, rec := range f.irps {
			if rec.rec.Header.Timestamp != ts {
				continue
			}
			irp := f.irps[i]
			irp.storeCallstack(r)
			f.irps[i] = irp
			return r, false
		}
		return r, true
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

		if irp.callstack == nil {
			fsApproverCallstackMisses.Add(1)
		}

		rec := irp.rec
		status := r.ReadUint32(16)
		// if the I/O status is different than file open
		// or the rules compilation result is not present
		// we'll allow events flow downstream processors
		if f.r == nil || disposition != windows.FILE_OPEN {
			irp.storeExtendedDataItems(disposition, status)
			f.irps[i] = irp
			return rec, true
		}

		s := rec.ConsumeRawUTF16String(32)
		h := hashFilePath(s)
		path, ok := f.pathLRUCache.Get(h)
		if !ok {
			n := utf16.Decode(s[:len(s)/2-1])
			path = devmapper.GetDevMapper().Convert(n)
			f.pathLRUCache.Add(h, path)
		}

		// evaluate against available approvers
		for _, approver := range f.approvers {
			if approver(path) {
				fsApproverApprovals.Add(1)
				irp.storeExtendedDataItems(disposition, status)
				f.irps[i] = irp
				return rec, true
			}
		}
		// the event is rejected by approvers
		irp.releasePools()
		delete(f.irps, i)
		fsApproverRejections.Add(1)
		return rec, false
	}

	return r, true
}

func (f *fs) cleanup(r *etw.EventRecord) {
	if r.Header.ProviderID == event.FileEventGUID && r.Header.EventDescriptor.Opcode == event.CreateFileID {
		i := r.ReadUint64(0)
		if irp, ok := f.irps[i]; ok {
			irp.releasePools()
			delete(f.irps, i)
		}
	}
}
