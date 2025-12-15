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

package ruleset

import (
	"net"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/util/convert"
)

// RuleAction wraps all possible rule actions.
type RuleAction any

// KillAction defines an action for killing the process.
type KillAction struct{}

// IsolateAction defines an action for isolating the host
// via firewall rules.
type IsolateAction struct {
	// Whitelist contains IP addresses that should remain accessible.
	Whitelist []net.IP `mapstructure:"whitelist"`
}

// ActionContext is the convenient structure
// for grouping the event that resulted in
// matched rule along with rule information.
type ActionContext struct {
	// Events contains a single element for simple rules
	// or a list of ordered matched events for sequence
	// rules
	Events []*event.Event
	// Filter represents the rule that matched the event
	Rule *Rule
}

// UniquePids returns a set of process identifiers
// from each matched event to be used in actions
// such as the process kill action.
func (ctx *ActionContext) UniquePids() []uint32 {
	pids := make(map[uint32]struct{})
	for _, e := range ctx.Events {
		if e.IsCreateProcess() {
			pids[e.Params.MustGetPid()] = struct{}{}
		} else {
			pids[e.PID] = struct{}{}
		}
	}
	return convert.MapKeysToSlice(pids)
}
