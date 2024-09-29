/*
 * Copyright 2021-2024 by Nedim Sabic Sabic
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

package ksource

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/kevent"
)

// EventSource defines the contract all event sources have to satisfy.
// ETW, kernel driver, or userspace instrumentation are all examples of
// event sources. The main responsibility of the event source is to capture
// the events emitted by the operating system, parse, enrich, and build
// the state that represents the foundation for the detection engine.
type EventSource interface {
	// Open starts the instrumentation machinery. It receives the global
	// configuration that the event source can utilize to influence how
	// the events are captured. Before opening the event source, it is
	// important to register any event listener that acts on behalf of the
	// received event. Likewise, if any filter must be set to drop unwanted
	// signals, it needs to be set before the event source is opened.
	Open(config *config.Config) error
	// Close performs event source shutdown. Once event source is closed,
	// any buffered or pending events are no longer dispatched to event
	// listeners.
	Close() error
	// Errors returns the channel that receives errors that are side effect
	// of event capture, parsing, or enrichment phase.
	Errors() <-chan error
	// Events return the channel where event source pushes all captured events.
	// At this point, the event has the full state associated with it. For example,
	// the full process state or the event call stack.
	Events() <-chan *kevent.Kevent
	// SetFilter attaches the filter to the event source. Only events that match
	// the filter are forwarded to the event source output channel.
	SetFilter(f filter.Filter)
	// RegisterEventListener installs event listener. Event listener represents any
	// component that satisfies the kevent.Listener interface. Event listener can
	// decide if the event is pushed to the output queue.
	RegisterEventListener(lis kevent.Listener)
}
