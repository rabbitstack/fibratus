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

package processors

import "github.com/rabbitstack/fibratus/pkg/kevent"

// ProcessorType is an alias for the processor type
type ProcessorType uint8

const (
	// Ps represents the process processor.
	Ps ProcessorType = iota
	// Fs represents the file system processor.
	Fs
	// Registry represents the registry processor.
	Registry
	// Image represents the image processor.
	Image
	// Net represents the network processor.
	Net
	// Handle represents the handle processor.
	Handle
	// Driver represents the driver processor.
	Driver
)

// Processor is the minimal interface that each event stream processor has to satisfy. Kernel stream processor
// has the ability to augment kernel event with additional parameters. It is also capable of building a state machine
// from the flow of events going through it. The processor can also decide to drop the inbound event by
// returning an error via its `ProcessEvent` method.
type Processor interface {
	// ProcessEvent receives an existing event possibly mutating its state. The event is filtered out if
	// this method returns an error. If it returns true, the next processor in the chain is evaluated.
	// Processor may return a single instance of the mutated event or a batch of multiple events
	ProcessEvent(*kevent.Kevent) (*kevent.Batch, bool, error)

	// Name returns a human-readable name of this processor.
	Name() ProcessorType

	// Close closes the processor and disposes allocated resources.
	Close()
}

// String returns a human-friendly processor name.
func (typ ProcessorType) String() string {
	switch typ {
	case Ps:
		return "process"
	case Fs:
		return "file"
	case Registry:
		return "registry"
	case Image:
		return "image"
	case Net:
		return "net"
	case Handle:
		return "handle"
	case Driver:
		return "driver"
	default:
		return "unknown"
	}
}
