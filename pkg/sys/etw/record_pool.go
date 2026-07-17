//go:build windows
// +build windows

/*
 * Copyright 2019-present by Nedim Sabic Sabic
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

package etw

import (
	"sync"
	"unsafe"
)

const bufSizeHint = 512

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, bufSizeHint)
		return &b
	},
}

var eventRecordPool = sync.Pool{
	New: func() any { return &EventRecord{} },
}

var fileExtDataPool = sync.Pool{
	New: func() any { return &FileExtendedDataItems{} },
}

func getBuf(n int) []byte {
	bp := bufPool.Get().(*[]byte)
	b := *bp
	if cap(b) < n {
		return make([]byte, n) // rare oversized event, pay the allocation once, don't repool it later
	}
	return b[:n]
}

func releaseBuf(b []byte) {
	if cap(b) > bufSizeHint*8 {
		return // drop outlier-sized buffers instead of pooling them permanently
	}
	b = b[:0]
	bufPool.Put(&b)
}

func getEventRecord() *EventRecord {
	return eventRecordPool.Get().(*EventRecord)
}

func getFileExtendedDataItems() *FileExtendedDataItems {
	return fileExtDataPool.Get().(*FileExtendedDataItems)
}

func (f *FileExtendedDataItems) ReleasePool() {
	f.callstack = nil // release reference, don't let pool retain a stale slice
	fileExtDataPool.Put(f)
}

// ReleasePool returns both the record and its backing buffer to their pools.
// Call only once the record is fully done being read by all downstream consumers.
func (r *EventRecord) ReleasePool() {
	if r.Buffer != 0 && r.BufferLen > 0 {
		buf := unsafe.Slice((*byte)(unsafe.Pointer(r.Buffer)), r.BufferLen)
		releaseBuf(buf)
	}
	*r = EventRecord{} // zero every field before returning to pool
	eventRecordPool.Put(r)
}
