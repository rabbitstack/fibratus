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

import (
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
)

// processorFailures counts the number of failures caused by event processors
var processorFailures = expvar.NewInt("kevent.processor.failures")

// Chain defines the event process chain has to satisfy.
type Chain interface {
	// ProcessEvent pushes the event into processor chain. Processors are applied sequentially, so we have to make
	// sure that any processor providing additional context to the next processor is defined first in the chain. If
	// one processor fails, the next processor in chain is invoked.
	ProcessEvent(kevt *kevent.Kevent) (*kevent.Kevent, error)
	// Close closes the processor chain and frees all allocated resources.
	Close() error
}

func (c *chain) addProcessor(processor Processor) {
	if processor == nil {
		return
	}
	c.processors = append(c.processors, processor)
}

func (c chain) ProcessEvent(kevt *kevent.Kevent) (*kevent.Kevent, error) {
	var errs = make([]error, 0)
	var evt *kevent.Kevent

	for _, processor := range c.processors {
		var err error
		var next bool
		evt, next, err = processor.ProcessEvent(kevt)
		if err != nil {
			processorFailures.Add(1)
			errs = append(errs, fmt.Errorf("%q processor failed with error: %v", processor.Name(), err))
			continue
		}
		if !next {
			break
		}
	}
	if len(errs) > 0 {
		return evt, multierror.Wrap(errs...)
	}

	return evt, nil
}

// Close closes the processor chain and frees all allocated resources.
func (c chain) Close() error {
	for _, processor := range c.processors {
		processor.Close()
	}
	return nil
}
