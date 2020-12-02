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

// Writer is the minimal interface that all kcap writers need to satisfy. The kcap file format has the layout as
// depicted in the following diagram:
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
	Write(chan *kevent.Kevent, chan error) chan error
	Close() error
}

// Reader offers the mechanism for recovering the state of the kcapture and replaying all captured events.
type Reader interface {
	Read(ctx context.Context) (chan *kevent.Kevent, chan error)
	Close() error
	RecoverSnapshotters() (handle.Snapshotter, ps.Snapshotter, error)
	SetFilter(f filter.Filter)
}
