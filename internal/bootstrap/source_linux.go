//go:build linux

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
	"github.com/rabbitstack/fibratus/pkg/config"
)

type EventSourceControl struct {
	evs *stubEventSource
}

func NewEventSourceControl(*config.Config) *EventSourceControl {
	return &EventSourceControl{evs: &stubEventSource{}}
}

func (s *EventSourceControl) Open(cfg *config.Config) error {
	return s.evs.Open(cfg)
}

func (s *EventSourceControl) Close() error {
	return s.evs.Close()
}

type stubEventSource struct{}

func (*stubEventSource) Open(*config.Config) error {
	return nil
}

func (*stubEventSource) Close() error { return nil }
