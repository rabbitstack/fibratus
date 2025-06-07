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

import (
	"github.com/rabbitstack/fibratus/pkg/util/hashers"
)

// Category is the type alias for event categories
type Category string

// Subcategory is the type alias for event subcategories
type Subcategory string

const (
	// Registry is the category for registry related events
	Registry Category = "registry"
	// File is the category for file system events
	File Category = "file"
	// Net is the category for network events
	Net Category = "net"
	// Process is the category for process events
	Process Category = "process"
	// Thread is the category for thread events
	Thread Category = "thread"
	// Image is the category for image events
	Image Category = "image"
	// Handle is the category for handle events
	Handle Category = "handle"
	// Driver is the category for driver events
	Driver Category = "driver"
	// Mem is the category for memory events
	Mem Category = "mem"
	// Object the category for object manager events
	Object Category = "object"
	// Threadpool is the category for thread pool events
	Threadpool Category = "threadpool"
	// Other is the category for uncategorized events
	Other Category = "other"
	// Unknown is the category for events that couldn't match any of the previous categories
	Unknown Category = "unknown"
)

const (
	// DNS designates the DNS (Domain Name Service) event subcategory
	DNS Subcategory = "dns"
	// None identifies no subcategory
	None Subcategory = "none"
)

// Hash obtains the hash of the category string.
func (c Category) Hash() uint32 {
	return hashers.FnvUint32([]byte(c))
}

// MaxCategoryIndex designates the maximum category index.
const MaxCategoryIndex = 13

// Index returns a numerical category index.
func (c Category) Index() uint8 {
	switch c {
	case Registry:
		return 1
	case File:
		return 2
	case Net:
		return 3
	case Process:
		return 4
	case Thread:
		return 5
	case Image:
		return 6
	case Handle:
		return 7
	case Driver:
		return 8
	case Mem:
		return 9
	case Object:
		return 10
	case Threadpool:
		return 11
	case Other:
		return 12
	default:
		return MaxCategoryIndex
	}
}

// Categories returns all available categories.
func Categories() []string {
	return []string{
		string(Registry),
		string(File),
		string(Net),
		string(Process),
		string(Thread),
		string(Image),
		string(Handle),
		string(Mem),
		string(Driver),
		string(Other),
		string(Unknown),
		string(Object),
		string(Threadpool),
	}
}
