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

package policy

import (
	_ "embed"
)

// //go:embed schemas/rule.schema.json
// var ruleSchema string

// //go:embed schemas/macro.schema.json
// var macroSchema string

// // DecodeRule decodes the rule definition from the YAML document. The
// // document is validated against the rule JSON schema and then rendered
// // as Go template before it is decoded into the RuleDef. The resource is
// // only used to build meaningful error messages.
// func DecodeRule(resource string, b []byte) (*RuleDef, error) {
// 	var out any
// 	if err := yaml.Unmarshal(b, &out); err != nil {
// 		return nil, fmt.Errorf("%q is an invalid yaml file: %v", resource, err)
// 	}
// 	if valid, errs := validateSchema(ruleSchema, out); !valid || len(errs) > 0 {
// 		return nil, invalidDefinitionError("rule", resource, out, errs)
// 	}
// 	var rule RuleDef
// 	if err := yaml.Unmarshal(b, &rule); err != nil {
// 		return nil, fmt.Errorf("%q: %v", resource, err)
// 	}
// 	if err := rule.Validate(); err != nil {
// 		return nil, fmt.Errorf("%q: %v", resource, err)
// 	}
// 	return &rule, nil
// }

// // DecodeMacros decodes the list of macro definitions from the YAML
// // document in the same way as DecodeRule does for rules.
// func DecodeMacros(resource string, b []byte) ([]*MacroDef, error) {
// 	var out any
// 	if err := yaml.Unmarshal(b, &out); err != nil {
// 		return nil, fmt.Errorf("%q is an invalid macro yaml file: %v", resource, err)
// 	}
// 	if valid, errs := validateSchema(macroSchema, out); !valid || len(errs) > 0 {
// 		return nil, invalidDefinitionError("macro", resource, out, errs)
// 	}
// 	var macros []*MacroDef
// 	if err := yaml.Unmarshal(b, &macros); err != nil {
// 		return nil, fmt.Errorf("%q: %v", resource, err)
// 	}
// 	for _, m := range macros {
// 		if err := m.Validate(); err != nil {
// 			return nil, fmt.Errorf("%q: %v", resource, err)
// 		}
// 	}
// 	return macros, nil
// }
