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

package bootstrap

import (
	"github.com/rabbitstack/fibratus/internal/etw"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/ksource"
	"github.com/rabbitstack/fibratus/pkg/ps"
)

// EventSourceControl abstracts away the management of event sources.
// Presently, system events are captured by ETW infra, in the future
// additional instrumentation engines can be introduced and the event
// source will automatically decide which is the best engine to operate
// with. As an example, eBPF instrumentation may gain traction in the
// future, and the systems that support eBPF can provide a richer spectrum
// of telemetry than the ETW subsystem. In this scenario, the event source
// control will bootstrap the instrumentation engine based on eBPF.
type EventSourceControl struct {
	evs ksource.EventSource
}

func NewEventSourceControl(
	psnap ps.Snapshotter,
	hsnap handle.Snapshotter,
	config *config.Config,
	compiler *config.RulesCompileResult,
) *EventSourceControl {
	return &EventSourceControl{evs: etw.NewEventSource(psnap, hsnap, config, compiler)}
}

func (s *EventSourceControl) Open(config *config.Config) error {
	return s.evs.Open(config)
}

func (s *EventSourceControl) Close() error {
	return s.evs.Close()
}

func (s *EventSourceControl) Errors() <-chan error {
	return s.evs.Errors()
}

func (s *EventSourceControl) Events() <-chan *kevent.Kevent {
	return s.evs.Events()
}

func (s *EventSourceControl) SetFilter(f filter.Filter) {
	s.evs.SetFilter(f)
}

func (s *EventSourceControl) RegisterEventListener(lis kevent.Listener) {
	s.evs.RegisterEventListener(lis)
}
