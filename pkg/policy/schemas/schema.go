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
	"errors"
	"fmt"

	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/xeipuuv/gojsonschema"
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

func ValidateRuleSchema(m any) (bool, []error) {
	return true, nil
}

func ValidateMacrosSchema(m any) (bool, []error) {
	return true, nil
}

func validateSchema(schema string, m any) (bool, []error) {
	converted, err := toStringKeys(m, "")
	if err != nil {
		return false, []error{fmt.Errorf("fail to convert keys to string: %v", err)}
	}
	r, err := gojsonschema.Validate(gojsonschema.NewStringLoader(schema), gojsonschema.NewGoLoader(converted))
	if err != nil {
		return false, []error{fmt.Errorf("fail to validate file through schema: %v", err)}
	}
	errs := make([]error, len(r.Errors()))
	for i, err := range r.Errors() {
		errs[i] = errors.New(err.String())
	}
	return r.Valid(), errs
}

// toStringKeys ensures YAML map keys are strings, as required by the JSON schema validator.
func toStringKeys(value any, prefix string) (any, error) {
	join := func(k string) string {
		if prefix == "" {
			return k
		}
		return prefix + "." + k
	}
	switch v := value.(type) {
	case map[string]any:
		dict := make(map[string]any, len(v))
		for k, e := range v {
			c, err := toStringKeys(e, join(k))
			if err != nil {
				return nil, err
			}
			dict[k] = c
		}
		return dict, nil
	case map[any]any:
		dict := make(map[string]any, len(v))
		for k, e := range v {
			ks, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("non-string key in %q: %#v", prefix, k)
			}
			c, err := toStringKeys(e, join(ks))
			if err != nil {
				return nil, err
			}
			dict[ks] = c
		}
		return dict, nil
	case []any:
		list := make([]any, 0, len(v))
		for i, e := range v {
			c, err := toStringKeys(e, fmt.Sprintf("%s[%d]", prefix, i))
			if err != nil {
				return nil, err
			}
			list = append(list, c)
		}
		return list, nil
	}
	return value, nil
}
