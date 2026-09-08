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
	"github.com/rabbitstack/fibratus/pkg/eval"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/policy"
)

type RuleEvaluator interface {
	Evaluate(evt *event.Event, valuer *eval.ValuerCache) ([]*event.Event, bool)
}

type Rule struct {
	evaluator     *eval.Evaluator
	ruleEvaluator RuleEvaluator
}

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

func (r *Rule) Evaluate(event *event.Event, valuer *eval.ValuerCache) ([]*event.Event, bool) {
	return r.ruleEvaluator.Evaluate(event, valuer)
}

func NewRule(ruleDef policy.RuleDef) (*Rule, error) {
	evaluator, err := eval.NewEvaluator(string(ruleDef.ID), ruleDef.Condition)
	if err != nil {
		return nil, err
	}

	var ruleEvaluator RuleEvaluator
	if evaluator.IsSequenceExpr() {
		ruleEvaluator = MakeSequenceEvaluator(evaluator)
	} else {
		ruleEvaluator = MakeDirectEvaluator(evaluator)
	}

	return &Rule{
		evaluator:     evaluator,
		ruleEvaluator: ruleEvaluator,
	}, nil
}
