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

// Consumer is the interface for the event stream consumer.
type Consumer interface {
	// Open starts capturing events from the source.
	Open() error
	// Close shutdowns event stream consumer.
	Close() error
	// Errors returns the channel where errors are pushed.
	Errors() <-chan error
	// Events returns the buffered channel where collected events are pushed.
	Events() <-chan *kevent.Kevent
	// SetFilter sets the filter to run on every captured event.
	SetFilter(filter.Filter)
	// RegisterEventListener registers a new event listener that is invoked before
	// the event is pushed to the output queue.
	RegisterEventListener(kevent.Listener)
}
