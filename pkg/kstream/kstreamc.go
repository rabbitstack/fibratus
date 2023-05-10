/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package kstream

import (
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/kevent"
)

// EventCallbackFunc is the type alias for the event callback function
type EventCallbackFunc func(*kevent.Kevent) error

// Consumer is the interface for the kernel event stream consumer.
type Consumer interface {
	// Open initializes the event stream by setting the event record callback and instructing it
	// to consume events from log buffers. This operation can fail if opening the kernel logger
	// session results in an invalid trace handler. Errors returned by `ProcessTrace` are sent
	// to the channel since this function blocks the current thread, so we schedule its execution
	// in a separate goroutine.
	Open([]TraceSession) error
	// Close shutdowns the currently running event stream consumer by closing the corresponding session.
	Close() error
	// Errors returns the channel where errors are pushed.
	Errors() chan error
	// Events returns the buffered channel for pulling collected kernel events.
	Events() chan *kevent.Kevent
	// SetFilter initializes the filter that's applied on the kernel events.
	SetFilter(filter.Filter)
	// SetEventCallback registers a callback function that is invoked on
	// each incoming event. If the callback function is set up, the events
	// are not pushed to the consumer output channel.
	SetEventCallback(EventCallbackFunc)
}
