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

package rules

import "net"

// Alerter emits the alert for the matched rule. The alert is the implicit
// action carried out for every rule match.
type Alerter interface {
	// Alert sends the alert about the match.
	Alert(m RuleMatch) error
}

// ProcessKiller terminates the processes that participated in the rule match.
type ProcessKiller interface {
	// Kill terminates the processes of the matched events.
	Kill(m RuleMatch) error
}

// Isolator isolates the host from the network.
type Isolator interface {
	// Isolate blocks all the network traffic, except
	// the traffic from and to the allowed addresses.
	Isolate(whitelist []net.IP) error
}

// Actions groups the implementations of the actions the engine can run on
// behalf of the rules. The implementations live outside of the rules package,
// since they depend on the event source internals and the host. Actions
// that are not provided are skipped, and the engine warns about them.
type Actions struct {
	Alerter       Alerter
	ProcessKiller ProcessKiller
	Isolator      Isolator
}
