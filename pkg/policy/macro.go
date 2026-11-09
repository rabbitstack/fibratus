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
	"fmt"
	"regexp"

	"github.com/rabbitstack/fibratus/pkg/policy/schemas"
	"gopkg.in/yaml.v3"
)

// MacroID represents the ID of a macro.
type MacroID = string

var macroIDRegexp = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// MacroDef is the definition of a macro. A macro either expands to
// an expression or to a list of values. The YAML keys are kept
// compatible with the macro library files that ship with Fibratus.
type MacroDef struct {
	// ID is the unique macro identifier.
	ID MacroID `yaml:"macro" json:"macro"`
	// Description describes the macro.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	// Expression is the expression the macro expands to. Mutually
	// exclusive with Values.
	Expression string `yaml:"expr,omitempty" json:"expr,omitempty"`
	// Values is the list of values the macro expands to. Mutually
	// exclusive with Expression.
	Values []string `yaml:"list,omitempty" json:"list,omitempty"`
}

// IsList determines if the macro expands to a list of values.
func (m *MacroDef) IsList() bool { return m.Expression == "" && m.Values != nil }

// Validate checks the structural validity of the macro definition.
func (m *MacroDef) Validate() error {
	if m.ID == "" {
		return fmt.Errorf("macro is missing the identifier")
	}
	if !macroIDRegexp.MatchString(m.ID) {
		return fmt.Errorf("%q is not a valid macro identifier", m.ID)
	}
	switch {
	case m.Expression != "" && m.Values != nil:
		return fmt.Errorf("macro %q cannot declare both expression and list", m.ID)
	case m.Expression == "" && m.Values == nil:
		return fmt.Errorf("macro %q must declare either expression or list", m.ID)
	}
	return nil
}

// MacroDefs is a list of macro definitions that validates itself on decode.
type MacroDefs []*MacroDef

// rawMacroDefs has no methods, so decoding into it doesn't re-enter
// MacroDefs.UnmarshalYAML.
type rawMacroDefs MacroDefs

// UnmarshalYAML implements yaml.Unmarshaler. The whole document is
// validated against the macro JSON schema first, then decoded and each
// macro is checked with Validate.
func (m *MacroDefs) UnmarshalYAML(node *yaml.Node) error {
	var v any
	if err := node.Decode(&v); err != nil {
		return fmt.Errorf("line %d: invalid macro yaml: %v", node.Line, err)
	}
	if valid, errs := schemas.ValidateMacrosSchema(v); !valid || len(errs) > 0 {
		return schemas.InvalidDefinitionError("macro", fmt.Sprintf("line %d", node.Line), v, errs)
	}
	return node.Decode((*rawMacroDefs)(m))
}
