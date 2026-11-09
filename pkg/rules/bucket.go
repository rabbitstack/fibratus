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
)

// RuleBucket groups the rules that are interested in the same event type. The
// rule set keeps one bucket per event type, so the event is only evaluated
// against the rules that can possibly match it.
// Rules are kept in the order they were added, which is the order in which
// they are loaded, so the evaluation order is deterministic.
type RuleBucket struct {
	rules  []*Rule
	fields []eval.Field
}

// AddRule adds the rule to the bucket. Adding the same rule twice is a no-op.
func (rb *RuleBucket) AddRule(rule *Rule) {
	//for _, field := range rule.Evaluator().GetFields() {
	// index := sort.SearchStrings(rb.fields, field)
	// if index < len(rb.fields) && rb.fields[index] == field {
	// 	continue
	// }
	// rb.fields = append(rb.fields, "")
	// copy(rb.fields[index+1:], rb.fields[index:])
	// rb.fields[index] = field
	//}

	// sort by policy, execution context, then by priority
	//sort.SliceStable(rb.rules, func(i, j int) bool {
	// sort by policy type
	// if rb.rules[i].Policy.InternalType != rb.rules[j].Policy.InternalType {
	// 	return rb.rules[i].Policy.InternalType == DefaultPolicyType
	// }

	// sort by priority
	//return rb.rules[i].Def.Priority > rb.rules[j].Def.Priority
	//})

	for _, r := range rb.rules {
		if r == rule {
			return
		}
	}
	rb.rules = append(rb.rules, rule)
}

// Rules returns the rules in the bucket in the order they were added.
func (b *RuleBucket) GetRules() []*Rule {
	return b.rules
}

// Len returns the number of rules in the bucket.
func (b *RuleBucket) Len() int {
	if b == nil {
		return 0
	}
	return len(b.rules)
}

// Fields returns the unique fields referenced by all rules in the bucket.
func (b *RuleBucket) Fields() []eval.Field {
	if b == nil {
		return nil
	}
	var (
		flds []eval.Field
		seen = make(map[string]struct{})
	)
	for _, r := range b.rules {
		for _, f := range r.evaluator.GetFields() {
			key := f.String() + "|" + f.BoundVar
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			flds = append(flds, f)
		}
	}
	return flds
}
