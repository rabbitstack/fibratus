// +build windows

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

package object

import (
	"os"
	"syscall"
)

var (
	kernel32    = syscall.NewLazyDLL("kernel32")
	createEvent = kernel32.NewProc("CreateEventA")
	setEvent    = kernel32.NewProc("SetEvent")
	resetEvent  = kernel32.NewProc("ResetEvent")
)

// Event is the type alias for event objects.
type Event uintptr

// NewEvent produces a new event with the specified flags.
func NewEvent(manualReset, isSignaled bool) (Event, error) {
	var reset uint8
	var signaled uint8
	if manualReset {
		reset = 1
	}
	if isSignaled {
		signaled = 1
	}
	handle, _, err := createEvent.Call(0, uintptr(reset), uintptr(signaled), 0)
	if handle == 0 {
		return Event(0), os.NewSyscallError("CreateEventA", err)
	}
	return Event(handle), nil
}

// Set sets the event object to the signaled state.
func (e Event) Set() error {
	errno, _, err := setEvent.Call(uintptr(e))
	if errno == 0 {
		return os.NewSyscallError("SetEvent", err)
	}
	return nil
}

// Reset sets the event object to the nonsignaled state.
func (e Event) Reset() error {
	errno, _, err := resetEvent.Call(uintptr(e))
	if errno == 0 {
		return os.NewSyscallError("ResetEvent", err)
	}
	return nil
}

// Close closes the handle allocated by the event object.
func (e Event) Close() error {
	return syscall.Close(syscall.Handle(e))
}
