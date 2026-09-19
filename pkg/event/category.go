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

// Category is the type alias for event categories
type Category uint8

// Subcategory is the type alias for event subcategories
type Subcategory uint8

const (
	// Registry is the category for registry related events
	Registry Category = iota + 1
	// File is the category for file system events
	File
	// Network is the category for network events
	Network
	// Process is the category for process events
	Process
	// Thread is the category for thread events
	Thread
	// Module is the category for module (dll, exe, sys) events
	Module
	// Memory is the category for memory events
	Memory
	// Object the category for object manager events
	Object
	// Other is the category for uncategorized events
	Other
	MaxCategory // sentinel
)

const (
	// DNS designates the DNS (Domain Name Service) event subcategory
	DNS            Subcategory = iota + 1
	MaxSubcategory             // sentinel
)

// String returns the category string representation.
func (c Category) String() string {
	switch c {
	case Registry:
		return "registry"
	case File:
		return "file"
	case Network:
		return "network"
	case Process:
		return "process"
	case Thread:
		return "thread"
	case Module:
		return "module"
	case Memory:
		return "memory"
	case Object:
		return "object"
	case Other:
		return "other"
	default:
		return "unknown"
	}
}

func (sc Subcategory) String() string {
	switch sc {
	case DNS:
		return "dns"
	default:
		return "unknown"
	}
}

var categories = map[string]Category{
	"registry": Registry,
	"file":     File,
	"network":  Network,
	"process":  Process,
	"thread":   Thread,
	"module":   Module,
	"memory":   Memory,
	"object":   Object,
	"other":    Other,
}

// NumCategories returns a total number of recognized categories.
func NumCategories() int { return len(categories) }

// ParseCategory converts the category from the bare string. Returns
// the category and the bool indicating if the conversion succeeded.
func ParseCategory(s string) (Category, bool) {
	c, ok := categories[s]
	return c, ok
}

// IsCategoryKnown indicates if the category is known given its name.
func IsCategoryKnown(s string) (exists bool) {
	_, exists = ParseCategory(s)
	return
}
