/*
 * Copyright 2021-2026 by Nedim Sabic Sabic
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
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"golang.org/x/sys/windows"
)

// ProviderInfo describes ETW provider metadata.
type ProviderInfo struct {
	// GUID is the globally unique identifier for the
	// ETW provider for which the session is started.
	GUID windows.GUID
	// Keywords is the bitmask of keywords that determine
	// the categories of events for the provider to emit.
	// The provider typically writes an event if the event's
	// keyword bits match any of the bits set in this value
	// or if the event has no keyword bits set. Only relevant
	// for providers that are enabled via etw.EnableProvider
	// API.
	Keywords uint64
	// EnableStacks indicates if callstacks are enabled for
	// this provider.
	EnableStacks bool
	// CaptureState requests that the provider log its state
	// information, such as rundown events.
	CaptureState bool
	//eventFilterDescriptors stores the provider-specific filters.
	eventFilterDescriptors []etw.EventFilterDescriptor
}

// HasEventFilterDescriptors returns true if the provider has filter descriptors.
func (p *ProviderInfo) HasEventFilterDescriptors() bool {
	return len(p.eventFilterDescriptors) > 0
}
