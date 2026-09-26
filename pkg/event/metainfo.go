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

package event

import "slices"

// Flags represents the event flags
type Flags uint8

// Info describes the event meta info such as human-readable name, category and description.
type Info struct {
	// Name is the human-readable representation of the event (e.g. CreateProcess, DeleteFile).
	Name string
	// Category designates the category to which event pertains. (e.g. process, network)
	Category Category
	// Subcategory designates the event subcategory if any. For example, the network category
	// can be further subcategorized, such as DNS subcategory.
	Subcategory Subcategory
	// Source describes the event source origin for this event. For example, if it was captured
	// from the NT Kernel Logger or eBPF raw syscall tracepoint.
	Source Source
	// Description is the short explanation that describes the purpose of the event.
	Description string
	// Flags describes additional properties of the event.
	Flags Flags
}

// All returns all event types.
func AllTypes() []Type {
	types := make([]Type, 0)
	for i := range table {
		if Type(i) == Unknown {
			continue
		}
		types = append(types, Type(i))
	}
	return types
}

// GetTypeInfo returns metadata about the specified event type.
func GetTypeInfo(typ Type) Info {
	return table[typ]
}

// NameToType converts a human-readable event name to its internal type representation.
func ParseType(s string) (Type, bool) {
	i := slices.IndexFunc(table[:], func(info Info) bool {
		return info.Name == s
	})
	if i == -1 {
		return Unknown, false
	}
	return Type(i), true
}

// IsKnown indicates if the event type is known given the event name.
func IsTypeKnown(s string) (exists bool) {
	_, exists = ParseType(s)
	return
}
