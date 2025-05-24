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

package cap

import (
	"context"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/ps"
)

// Writer is the minimal interface that all cap writers need to satisfy. The Windows cap
// file format has the layout as depicted in the following diagram:
//
//	 +-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-++-+-+-+
//	 | Magic Number  | Major | Minor | Flags |
//		|----------------------------------------
//	 | Handle Section |       Handles        |
//	 -----------------------------------------
//	 | evt Section | evt ..................|
//		| ......................................|
//		| ......................................|
//		| ......................................|
//	 | ........ evt Section n  evt n  EOF  |
//	 +-+-+-+-+-+-+-+-++-+-+-+-+-+-+-+-++-+-+-+
type Writer interface {
	// Write accepts two channels. The event channel receives events pushed by the event consumer.
	// When the event is peeked from the channel, it is serialized and written to the underlying
	// byte buffer.
	Write(<-chan *event.Event, <-chan error) chan error
	// Close disposes all resources allocated by the writer.
	Close() error
}

// Reader offers the mechanism for recovering the state of the capture and replaying all captured events.
type Reader interface {
	// Read returns two channels. The event channel is populated with event instances pulled from the cap. If
	// any error occurs during capture processing, it is pushed to the error channel.
	Read(ctx context.Context) (chan *event.Event, chan error)
	// Close shutdowns the reader gracefully.
	Close() error
	// RecoverSnapshotters recovers the state of the snapshotters from the cap.
	RecoverSnapshotters() (handle.Snapshotter, ps.Snapshotter, error)
	// SetFilter sets the filter applied to each event coming out of the cap.
	SetFilter(f filter.Filter)
}
