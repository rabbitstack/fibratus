//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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

// AlwaysAllowed reports event types the process snapshotter consumes. Dropping
// one in the kernel would desynchronize process identity from live tasks, so no
// prefilter is ever installed for them regardless of what the rules ask for.
// Mirrored by the leading check in event_approved in c/common/approvers.h.
func AlwaysAllowed(t event.Type) bool {
	switch t {
	case event.Execve, event.Exit, event.Clone, event.UnknownType:
		return true
	default:
		return false
	}
}
