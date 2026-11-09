/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

import "github.com/rabbitstack/fibratus/pkg/event"

// Filter decides which events continue their journey through the event
// pipeline. It is built from a single filter expression that is typically
// supplied in the command line or by a filament. Filters are not rules, so
// sequences are not allowed. Rules are evaluated by the rule engine.
type Filter interface {
	// Eval evaluates the event against the filter expression. Returns true
	// if the filter has matched the event, or false otherwise. It is safe to
	// call it from multiple goroutines.
	Eval(evt *event.Event) bool
}
