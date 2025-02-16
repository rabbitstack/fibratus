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

import (
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter/action"
	log "github.com/sirupsen/logrus"
)

// processActions executes rule actions
// on behalf of rule matches. Actions are
// categorized into implicit and explicit
// actions.
// Sending an alert is an implicit action
// carried out each time there is a rule
// match. Other actions are executed if
// defined in the rule definition.
func (r *Rules) processActions() error {
	defer r.clearMatches()
	for _, m := range r.matches {
		f, evts := m.ctx.Filter, m.ctx.Events
		filterMatches.Add(f.Name, 1)
		log.Debugf("[%s] rule matched", f.Name)
		err := action.Emit(m.ctx, f.Name, InterpolateFields(f.Output, evts), f.Severity, f.Tags)
		if err != nil {
			return ErrRuleAction(f.Name, err)
		}

		actions, err := f.DecodeActions()
		if err != nil {
			return err
		}

		for _, act := range actions {
			switch t := act.(type) {
			case config.KillAction:
				log.Infof("executing kill action: pids=%v rule=%s", m.ctx.UniquePids(), f.Name)
				if err := action.Kill(m.ctx.UniquePids()); err != nil {
					return ErrRuleAction(f.Name, err)
				}
			case config.IsolateAction:
				log.Infof("executing isolate action: rule=%s", f.Name)
				if err := action.Isolate(t.Whitelist); err != nil {
					return ErrRuleAction(f.Name, err)
				}
			}
		}
	}

	return nil
}
