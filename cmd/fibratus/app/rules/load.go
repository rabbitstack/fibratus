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
	"fmt"
	"strings"

	"github.com/enescakir/emoji"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/rabbitstack/fibratus/pkg/rules"
)

// loadRuleSet loads the policies from the configured rule and macro paths and
// builds the rule set. Disabled rules are loaded too, if all is set, so they are
// validated as well. The rule set build error enumerates all the invalid rules.
func loadRuleSet(all bool) (*rules.RuleSet, error) {
	opts := policy.DefaultLoadOptions()
	if all {
		opts = policy.LoadOptions{}
	}
	loader := policy.NewLoader(opts, policy.NewDirProvider(cfg.Rules.RulePaths, cfg.Rules.MacroPaths))
	policies, err := loader.Load()
	if err != nil {
		return nil, fmt.Errorf("%v %v", emoji.DisappointedFace, err)
	}
	rs, err := rules.NewRuleSet(policies, rules.WithMatchAll(cfg.Rules.MatchAll))
	if err != nil {
		return nil, fmt.Errorf("%v %v", emoji.DisappointedFace, err)
	}
	if rs.Len() == 0 && len(rs.Report().Discarded) == 0 {
		return nil, fmt.Errorf("%v no rules found in %s", emoji.DisappointedFace, strings.Join(cfg.Rules.RulePaths, ","))
	}
	return rs, nil
}
