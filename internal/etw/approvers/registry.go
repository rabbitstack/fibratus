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

	"github.com/zeebo/xxh3"

	"github.com/rabbitstack/fibratus/pkg/util/utf16"

	"github.com/hashicorp/golang-lru/v2/expirable"
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

	pathLRUCache *expirable.LRU[uint64, string] // interned KCB paths
}

func newRegistryApprover(r *config.RulesCompileResult) Approver {
	return &registry{
		approver: approver{
			r: r,
		},
		kcbs:         make(map[uint64]string, 5000),
		pathLRUCache: expirable.NewLRU[uint64, string](1000, nil, time.Minute*5),
	}
}

func hashKeyPath(r string, u []uint16) uint64 {
	var h xxh3.Hasher

	b := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(u))), len(u))
	_, _ = h.Write(b)
	if r != "" {
		k := unsafe.Slice(unsafe.StringData(r), len(r))
		_, _ = h.Write(k)
	}

	return h.Sum64()
}

func (r *registry) Approve(rec *etw.EventRecord) (*etw.EventRecord, bool) {
	if rec.Header.ProviderID != event.RegistryEventGUID {
		return rec, true
	}

	id := rec.Header.EventDescriptor.Opcode

	// keep the state of allocated key control blocks
	// to be able to derive the full registry path
	if id == event.RegKCBRundownID || id == event.RegCreateKCBID {
		kcb := rec.ReadUint64(16)
		path := rec.ConsumeUTF16String(24)
		r.kcbs[kcb] = path
		return rec, true
	}
	// remove kcb mapping
	if id == event.RegDeleteKCBID {
		kcb := rec.ReadUint64(16)
		r.pathLRUCache.Purge()
		delete(r.kcbs, kcb)
		return rec, true
	}

	// accept all but key access events
	if id != event.RegOpenKeyID {
		return rec, true
	}

	// calculate the hash and check against LRU cache
	kcb := rec.ReadUint64(16)
	s := rec.ConsumeRawUTF16String(24)
	h := hashKeyPath(r.kcbs[kcb], s)
	path, ok := r.pathLRUCache.Get(h)
	if !ok {
		// lookup KCB map to check if the event
		// KCB object address references a key
		// we can use to reconstruct the full
		// registry path
		path = utf16.Decode(s[:len(s)/2-1])
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
		r.pathLRUCache.Add(h, path)
	}

	if r.approveKey(path) {
		registryApproverApprovals.Add(1)
		return rec, true
	}

	registryApproverRejections.Add(1)

	return rec, false
}
