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

package etw

import (
	"github.com/rabbitstack/fibratus/internal/etw/processors"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
)

// Consumer is the core component in the event processing pipeline.
// The raw event is offloaded from the session buffer, then parsed
// and converted to typed representation with process state attached
// to it. The event consumer is responsible for enriching the event
// with additional attributes. The event is sent to the queue where
// all registered listeners are executed.
type Consumer struct {
	q          *kevent.Queue
	sequencer  *kevent.Sequencer
	processors processors.Chain
	psnap      ps.Snapshotter
	config     *config.Config
	filter     filter.Filter
	isClosing  bool
}

// NewConsumer builds a new event consumer.
func NewConsumer(
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
	sequencer *kevent.Sequencer,
	evts chan *kevent.Kevent,
) *Consumer {
	return &Consumer{
		q:          kevent.NewQueueWithChannel(evts, config.Kstream.StackEnrichment, config.ForwardMode || config.IsCaptureSet()),
		sequencer:  sequencer,
		processors: processors.NewChain(psnap, hsnap, config),
		psnap:      psnap,
		config:     config,
	}
}

func (c *Consumer) SetFilter(f filter.Filter) {
	c.filter = f
}

func (c *Consumer) Close() error {
	c.isClosing = true
	return c.processors.Close()
}

func (c *Consumer) ProcessEvent(ev *etw.EventRecord) error {
	if c.isClosing {
		return nil
	}
	if kevent.IsCurrentProcDropped(ev.Header.ProcessID) {
		return nil
	}
	if c.config.Kstream.ExcludeKevent(ev.Header.ProviderID, ev.HookID()) {
		excludedKevents.Add(1)
		return nil
	}

	ktype := ktypes.NewFromEventRecord(ev)
	if !ktype.Exists() {
		keventsUnknown.Add(1)
		return nil
	}

	keventsProcessed.Add(1)
	evt := kevent.New(c.sequencer.Get(), ktype, ev)

	// Dispatch each event to the processor chain.
	// Processors may further augment the event with
	// useful fields or play the role of state managers.
	// Scanning open files and registry control blocks
	// at the beginning of the kernel trace session is an
	// example of state management
	var err error
	evt, err = c.processors.ProcessEvent(evt)
	if err != nil {
		return err
	}
	if evt.WaitEnqueue {
		return nil
	}
	ok, proc := c.psnap.Find(evt.PID)
	if !ok {
		c.psnap.Put(proc)
	}

	// Associate process' state with the event.
	// We only override the process' state if it hasn't
	// been set previously such as in the situation where
	// captures are being taken. Events that construct
	// the process' snapshot also have attached process
	// state, so simply by replaying the flow of these
	// events we are able to reconstruct system-wide
	// process state.
	if evt.PS == nil {
		evt.PS = proc
	}
	// Drop any events if it is originated by the
	// current process, state event, or if the
	// process image is in the exclusion list.
	// Stack walk events are forwarded to the
	// event queue for stack enrichment. Lastly,
	// the filter is evaluated on the event to
	// decide whether it should get dropped
	if (evt.IsDropped(c.config.IsCaptureSet()) ||
		c.config.Kstream.ExcludeImage(evt.PS)) && !evt.IsStackWalk() {
		keventsDropped.Add(1)
		return nil
	}
	if c.filter != nil && !evt.IsStackWalk() && !c.filter.Run(evt) {
		return nil
	}
	// Increment sequence
	if !evt.IsState() {
		c.sequencer.Increment()
	}

	return c.q.Push(evt)
}
