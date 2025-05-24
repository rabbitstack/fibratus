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

package section

// Type describes the type of the capture section
type Type uint8

const (
	// Process is the process header type
	Process Type = iota + 1
	// Handle is the handle header type
	Handle
	// Event is the event header type
	Event
	// PE is the Portable Executable header type
	PE
)

// String returns the type name.
func (s Type) String() string {
	switch s {
	case Process:
		return "process"
	case Handle:
		return "handle"
	case Event:
		return "event"
	case PE:
		return "pe"
	default:
		return ""
	}
}
