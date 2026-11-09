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

package bootstrap

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/rules"
)

// engineListener adapts the rule engine to the event queue listener
// interface. The engine only evaluates the events, so the listener
// decides if the event continues its journey based on the outcome.
type engineListener struct {
	engine *rules.Engine
}

func newEngineListener(engine *rules.Engine) event.Listener {
	return &engineListener{engine: engine}
}

// ProcessEvent evaluates the event against the rule set. The event is
// enqueued only if it triggered at least one rule, which is signaled by the
// engine through the rule name in the event metadata. If the rule set is
// empty, the events are not enqueued either, since there is nothing to alert on.
func (l *engineListener) ProcessEvent(evt *event.Event) (bool, error) {
	if err := l.engine.HandleEvent(evt); err != nil {
		return false, err
	}
	return evt.GetMetaAsString(event.RuleNameKey) != "", nil
}

// CanEnqueue indicates the rule engine decides on the event queueing.
func (*engineListener) CanEnqueue() bool { return true }
