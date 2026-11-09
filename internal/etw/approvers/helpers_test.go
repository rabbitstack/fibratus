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

package approvers

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/rabbitstack/fibratus/pkg/rules"
	"github.com/stretchr/testify/require"
)

// newProvider builds the rule set from the rule conditions and returns it as
// the approvers provider, exactly as the rule engine does in production.
func newProvider(t *testing.T, conditions ...string) rules.ApproversProvider {
	t.Helper()
	defs := make([]*policy.RuleDef, 0, len(conditions))
	for i, c := range conditions {
		defs = append(defs, &policy.RuleDef{
			ID:        policy.RuleID(fmt.Sprintf("rule-%d", i)),
			Name:      fmt.Sprintf("rule %d", i),
			Condition: c,
		})
	}
	rs, err := rules.NewRuleSet([]*policy.Policy{{
		ID:     "approvers",
		Name:   "approvers",
		Source: "approvers",
		Type:   policy.BehaviourPolicyType,
		Rules:  defs,
	}})
	require.NoError(t, err)
	return rs
}

// list renders the values as the rule condition list literal.
func list(vals ...string) string {
	quoted := make([]string, 0, len(vals))
	for _, v := range vals {
		quoted = append(quoted, "'"+strings.ReplaceAll(v, `\`, `\\`)+"'")
	}
	return "(" + strings.Join(quoted, ", ") + ")"
}

// fileRule is the file open rule with the extra predicate.
func fileRule(pred string) string {
	return "evt.name = 'CreateFile' and file.operation = 'OPEN' and " + pred
}

// regRule is the registry key open rule with the extra predicate.
func regRule(pred string) string {
	return "evt.name = 'RegOpenKey' and " + pred
}

// procRule is the process open rule with the extra predicate.
func procRule(pred string) string {
	return "evt.name = 'OpenProcess' and " + pred
}
