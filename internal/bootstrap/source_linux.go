//go:build linux

/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
 * Copyright 2026 by Mostafa Moradian
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
	libebpf "github.com/rabbitstack/fibratus/internal/ebpf"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/source"
)

// EventSourceControl abstracts away the management of event sources.
type EventSourceControl struct {
	evs source.EventSource
}

func NewEventSourceControl(
	psnap ps.Snapshotter,
	cfg *config.Config,
	compiler *config.RulesCompileResult,
) *EventSourceControl {
	return &EventSourceControl{evs: libebpf.NewEventSource(psnap, cfg, compiler)}
}

func (s *EventSourceControl) Open(cfg *config.Config) error {
	return s.evs.Open(cfg)
}

func (s *EventSourceControl) Close() error {
	return s.evs.Close()
}

func (s *EventSourceControl) Errors() <-chan error {
	return s.evs.Errors()
}

func (s *EventSourceControl) Events() <-chan *event.Event {
	return s.evs.Events()
}

func (s *EventSourceControl) SetFilter(f filter.Filter) {
	s.evs.SetFilter(f)
}

func (s *EventSourceControl) RegisterEventListener(lis event.Listener) {
	s.evs.RegisterEventListener(lis)
}
