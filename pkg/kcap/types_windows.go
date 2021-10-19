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

package kcap

import (
	"context"

	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/ps"
)

// Writer is the minimal interface that all kcap writers need to satisfy. The Windows kcap
// file format has the layout as depicted in the following diagram:
//
//  +-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-++-+-+-+
//  | Magic Number  | Major | Minor | Flags |
//	|----------------------------------------
//  | Handle Section |       Handles        |
//  -----------------------------------------
//  | Kevt Section | Kevt ..................|
// 	| ......................................|
//	| ......................................|
//	| ......................................|
//  | ........ Kevt Section n  Kevt n  EOF  |
//  +-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-++-+-+-+
//
type Writer interface {
	// Write accepts two channels. The event channel receives events pushed by the kstream consumer. When the event
	// is peeked from the channel, it is serialized and written to the underlying byte buffer.
	Write(chan *kevent.Kevent, chan error) chan error
	// Close disposes all resources allocated by the writer.
	Close() error
}

// EndOfKcap contains kcap stats at the end of kcap read.
type EndOfKcap struct {
	KeventsRead int64
}

// Reader offers the mechanism for recovering the state of the kcapture and replaying all captured events.
type Reader interface {
	// Read returns two channels. The event channel is poplated with event instances pulled from the kcap. If
	// any error occurs during kcap processing, it is pushed to the error channel. The end of kcap channel
	// receives the signal to inform consumers that the end of the kcap is reached.
	Read(ctx context.Context) (chan *kevent.Kevent, chan EndOfKcap, chan error)
	// Close shutdowns the reader gracefully.
	Close() error
	// RecoverSnapshotters recovers the state of the snapshotters from the kcap.
	RecoverSnapshotters() (handle.Snapshotter, ps.Snapshotter, error)
	// ForwardSnapshotters recovers snapshotters without returning them. It is the alias for RecoverSnapshotters.
	ForwardSnapshotters() error
	// SetFilter sets the filter that is applied to each event coming out of the kcap.
	SetFilter(f filter.Filter)
}
