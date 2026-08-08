//go:build linux

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package filter

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
)

// noopAccessor satisfies Accessor for Windows-only field families on Linux.
type noopAccessor struct{}

func (noopAccessor) Get(Field, *event.Event) (params.Value, error) { return nil, nil }
func (noopAccessor) SetFields([]Field)                             {}
func (noopAccessor) SetSegments([]fields.Segment)                  {}
func (noopAccessor) IsFieldAccessible(*event.Event) bool           { return false }

func newThreadAccessor() Accessor     { return noopAccessor{} }
func newModuleAccessor() Accessor     { return noopAccessor{} }
func newFileAccessor() Accessor       { return noopAccessor{} }
func newRegistryAccessor() Accessor   { return noopAccessor{} }
func newNetworkAccessor() Accessor    { return noopAccessor{} }
func newHandleAccessor() Accessor     { return noopAccessor{} }
func newPEAccessor() Accessor         { return noopAccessor{} }
func newMemAccessor() Accessor        { return noopAccessor{} }
func newDNSAccessor() Accessor        { return noopAccessor{} }
func newThreadpoolAccessor() Accessor { return noopAccessor{} }
