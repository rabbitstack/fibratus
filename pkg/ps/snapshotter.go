/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package ps

import (
	"github.com/rabbitstack/fibratus/pkg/kevent"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

// Snapshotter is the interface that exposes a set of methods all process snapshotters have to satisfy. It stores the state
// of all running processes in the system including its threads, dynamically referenced libraries, handles/file descriptors and other
// metadata.
type Snapshotter interface {
	// Write appends a new process state to the snapshotter. It takes as an input the inbound kernel event to fetch
	// the basic data, but also enriches the process' state with extra metadata such as process' env variables, PE
	// metadata for Windows binaries and so on.
	Write(kevt *kevent.Kevent) error
	// WriteFromKcap appends a new process state to the snapshotter from the captured kernel event.
	WriteFromKcap(kevt *kevent.Kevent) error
	// Remove deletes process's state from the snapshotter.
	Remove(kevt *kevent.Kevent) error
	// Find attempts to retrieve process' state for the specified process identifier.
	Find(pid uint32) *pstypes.PS
	// Size returns the total number of process state items.
	Size() uint32
	// Close closes process snapshotter and disposes all allocated resources.
	Close() error
}
