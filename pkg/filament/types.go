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

package filament

import (
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/kevent"
)

// Filament defines the set of operations all filaments have to satisfy. Filament represents a full-fledged
// Python interpreter that runs the modules given by users.
type Filament interface {
	// Run consumes all events from the kernel event stream and dispatches them to the filament.
	Run(<-chan *kevent.Kevent, <-chan error) error
	// Close shutdowns the filament by releasing all allocated resources.
	Close() error
	// Filter returns the filter compiled from filament.
	Filter() filter.Filter
}

// Info stores metadata about the filament.
type Info struct {
	Name        string
	Description string
}
