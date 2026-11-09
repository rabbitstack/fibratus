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

import (
	"github.com/rabbitstack/fibratus/pkg/compiler/macro"
	"github.com/rabbitstack/fibratus/pkg/eval"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/policy"
)

type RuleEvaluator interface {
	Evaluate(evt *event.Event, valuer *eval.ValuerCache) ([]*event.Event, bool)
}

type NullEvaluator struct{}

type DirectEvaluator struct {
	evaluator *eval.Evaluator
}

func MakeDirectEvaluator(evaluator *eval.Evaluator) RuleEvaluator {
	return &DirectEvaluator{evaluator: evaluator}
}

func (e *DirectEvaluator) Evaluate(evt *event.Event, valuer *eval.ValuerCache) ([]*event.Event, bool) {
	if e.evaluator.Eval(evt, valuer) {
		return []*event.Event{evt}, true
	}
	return nil, false
}

// Rule is the compiled rule definition.
type Rule struct {
	*policy.RuleDef

	// Source designates where the rule comes from.
	Source string

	// order is the position of the rule in the rule set. It makes
	// the evaluation order deterministic.
	order int

	evaluator     *eval.Evaluator
	ruleEvaluator RuleEvaluator
}

// Evaluate evaluates the event against the rule. If the rule matches, the events
// that participated in the match are returned. Simple rules always match
// with the evaluated event, while sequences return the ordered events of all steps.
func (r *Rule) Evaluate(event *event.Event, valuer *eval.ValuerCache) ([]*event.Event, bool) {
	return r.ruleEvaluator.Evaluate(event, valuer)
}

// IsSequence determines if the rule condition is a sequence.
func (r *Rule) IsSequence() bool { return r.evaluator.IsSequenceExpr() }

// GetEventTypes returns the events the rule can match.
func (r *Rule) GetEventTypes() []event.Type { return r.evaluator.GetEventTypes() }

// Evaluator returns the underlying expression evaluator.
func (r *Rule) Evaluator() *eval.Evaluator { return r.evaluator }

// NewRule compiles the rule definition. The condition is parsed and its macros
// are expanded with the given macro store, which may be nil.
func NewRule(ruleDef *policy.RuleDef, macros *macro.Store) (*Rule, error) {
	evaluator, err := eval.NewEvaluator(string(ruleDef.ID), ruleDef.Condition, eval.WithMacros(macros))
	if err != nil {
		return nil, err
	}

	var ruleEvaluator RuleEvaluator
	if evaluator.IsSequenceExpr() {
		ruleEvaluator, err = MakeSequenceEvaluator(evaluator)
		if err != nil {
			return nil, err
		}
	} else {
		ruleEvaluator = MakeDirectEvaluator(evaluator)
	}

	return &Rule{
		RuleDef:       ruleDef,
		evaluator:     evaluator,
		ruleEvaluator: ruleEvaluator,
	}, nil
}
