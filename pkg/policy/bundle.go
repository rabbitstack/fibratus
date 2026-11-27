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

package policy

import (
	"errors"
	"fmt"
	"io"

	"github.com/rabbitstack/fibratus/pkg/policy/schemas"
	"gopkg.in/yaml.v3"
)

// yamlDefinition represents a YAML definition together with
// the source from which it was loaded.
type yamlDefinition struct {
	source string
	node   *yaml.Node
}

// YAMLBundleAdder represents a bundle that can accept YAML definitions
// from an io.Reader.
type YAMLBundleAdder interface {
	AddFrom(source string, r io.Reader) error
}

// YAMLBundle is a generic collection of YAML definitions.
//
// It preserves the original YAML nodes until definitions are
// decoded into their corresponding Go types.
type YAMLBundle[T any] struct {
	definitions []yamlDefinition
	validate    func(any) error
}

// NewYAMLBundle creates an empty YAMLBundle.
//
// validate is the schema validation function for the definition type.
func NewYAMLBundle[T any](validate func(any) error) *YAMLBundle[T] {
	return &YAMLBundle[T]{
		definitions: make([]yamlDefinition, 0),
		validate:    validate,
	}
}

// Add reads YAML definitions from r and adds them to the bundle.
func (b *YAMLBundle[T]) Add(r io.Reader) error {
	return b.AddFrom("reader", r)
}

// AddFrom reads YAML definitions from r and associates them with
// the provided source name.
//
// A YAML document can contain either a single mapping or a sequence
// of mappings. Multiple YAML documents are supported.
//
// Empty and null documents are ignored.
//
// The addition is transactional: definitions are added only after
// the entire input has been successfully decoded.
func (b *YAMLBundle[T]) AddFrom(source string, r io.Reader) error {
	dec := yaml.NewDecoder(r)

	var definitions []yamlDefinition

	for {
		var doc yaml.Node

		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%s: decode YAML: %w", source, err)
		}

		if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
			continue
		}

		root := doc.Content[0]

		switch root.Kind {
		case yaml.MappingNode:
			definitions = append(definitions, yamlDefinition{
				source: source,
				node:   root,
			})
		case yaml.SequenceNode:
			for _, item := range root.Content {
				if item.Kind != yaml.MappingNode {
					return fmt.Errorf(
						"%s:%d: expected a definition mapping in sequence",
						source,
						item.Line,
					)
				}
				definitions = append(definitions, yamlDefinition{
					source: source,
					node:   item,
				})
			}
		case yaml.ScalarNode:
			if root.Tag == "!!null" {
				continue
			}
			return fmt.Errorf(
				"%s:%d: expected a definition mapping or a sequence of definitions",
				source,
				root.Line,
			)
		default:
			return fmt.Errorf(
				"%s:%d: expected a definition mapping or a sequence of definitions",
				source,
				root.Line,
			)
		}
	}

	b.definitions = append(b.definitions, definitions...)

	return nil
}

// Validate validates every definition against its JSON schema.
//
// All validation errors are collected and returned together.
func (b *YAMLBundle[T]) Validate() error {
	var errs []error

	for i, definition := range b.definitions {
		var content any

		if err := definition.node.Decode(&content); err != nil {
			errs = append(errs, fmt.Errorf(
				"%s: decode definition %d for schema validation: %w",
				definition.source,
				i+1,
				err,
			))
			continue
		}

		if b.validate == nil {
			return errors.New("YAML bundle has no schema validator")
		}

		if err := b.validate(content); err != nil {
			errs = append(errs, fmt.Errorf(
				"%s: definition %d: schema validation failed: %w",
				definition.source,
				i+1,
				err,
			))
		}
	}

	return errors.Join(errs...)
}

// Definitions decodes all accumulated definitions into T.
//
// The returned definitions preserve the order in which they
// were added to the bundle.
func (b *YAMLBundle[T]) Definitions() ([]*T, error) {
	definitions := make([]*T, 0, len(b.definitions))

	for i, definition := range b.definitions {
		var value T

		if err := definition.node.Decode(&value); err != nil {
			return nil, fmt.Errorf(
				"%s: unmarshal definition %d: %w",
				definition.source,
				i+1,
				err,
			)
		}
		definitions = append(definitions, &value)
	}

	return definitions, nil
}

// Len returns the number of definitions in the bundle.
func (b *YAMLBundle[T]) Len() int {
	return len(b.definitions)
}

// Empty reports whether the bundle contains any definitions.
func (b *YAMLBundle[T]) Empty() bool {
	return len(b.definitions) == 0
}

type RuleBundle struct {
	*YAMLBundle[RuleDef]
}

func NewRuleBundle() *RuleBundle {
	return &RuleBundle{
		YAMLBundle: NewYAMLBundle[RuleDef](schemas.ValidateRuleSchema),
	}
}

func (b *RuleBundle) AddRule(r io.Reader) error {
	return b.Add(r)
}

func (b *RuleBundle) Validate() error {
	return b.YAMLBundle.Validate()
}

func (b *RuleBundle) Rules() ([]*RuleDef, error) {
	return b.Definitions()
}

type MacroBundle struct {
	*YAMLBundle[MacroDef]
}

func NewMacroBundle() *MacroBundle {
	return &MacroBundle{
		YAMLBundle: NewYAMLBundle[MacroDef](schemas.ValidateMacrosSchema),
	}
}

func (b *MacroBundle) AddMacro(r io.Reader) error {
	return b.Add(r)
}

func (b *MacroBundle) AddMacroFrom(source string, r io.Reader) error {
	return b.AddFrom(source, r)
}

func (b *MacroBundle) Validate() error {
	return b.YAMLBundle.Validate()
}

func (b *MacroBundle) Macros() ([]*MacroDef, error) {
	return b.Definitions()
}
