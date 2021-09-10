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

package kstream

import (
	"expvar"

	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
)

var (
	// failedKevents counts the number of kevents that failed to process grouped by error
	failedKevents = expvar.NewMap("kstream.kevents.failures")
)

// Consumer is the interface all kernel event stream consumers have to satisfy.
type Consumer interface {
	// OpenKstream initializes the kernel event stream by setting up the required
	// infrastructure for event collection.
	OpenKstream() error
	// CloseKstream shutdowns the currently running kernel event stream consumer by closing the corresponding
	// session.
	CloseKstream() error
	// Errors returns the channel where errors are pushed.
	Errors() chan error
	// Events returns the buffered channel for pulling collected kernel events.
	Events() chan *kevent.Kevent
	// SetFilter initializes the filter that's applied on the kernel events.
	SetFilter(filter filter.Filter)
}

type blacklist map[ktypes.Ktype]string

func (b blacklist) has(ktype ktypes.Ktype) bool { return b[ktype] != "" }
