/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package schemas

import (
	_ "embed"
	"fmt"

	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/rabbitstack/fibratus/pkg/util/schemavalidate"
	"gopkg.in/yaml.v2"
)

//go:embed rule.schema.json
var ruleSchema string

//go:embed macro.schema.json
var macroSchema string

func InvalidDefinitionError(kind, resource string, def any, errs []error) error {
	if b, err := yaml.Marshal(&def); err == nil {
		def = string(b)
	}
	return fmt.Errorf("invalid %s definition: \n\n%v in %s: %v", kind, def, resource, multierror.Wrap(errs...))
}

func ValidateRuleSchema(m any) (bool, error) {
	schema, err := schemavalidate.NewFromString(ruleSchema)
	if err != nil {
		return false, err
	}
	err = schema.Validate(m)
	return err == nil, err
}

func ValidateMacrosSchema(m any) (bool, []error) {
	return true, nil
}
