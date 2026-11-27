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

// Package schemavalidate validates arbitrary Go values (typically decoded
// YAML or JSON configuration) against a JSON Schema.
//
// It is a thin layer over github.com/xeipuuv/gojsonschema that
//
//   - normalizes YAML-style map[interface{}]interface{} documents so they can
//     be validated (see NormalizeKeys),
//   - reports problems as typed errors (*ValidationError, *FieldError,
//     *KeyError) instead of a bool plus an error slice, and
//   - lets you compile a schema once and validate many documents.
package schemavalidate

import (
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

// Validator validates documents against a schema that was compiled once.
type Validator struct {
	schema *gojsonschema.Schema
}

// New compiles a JSON Schema given as JSON bytes.
func New(schema []byte) (*Validator, error) {
	return NewFromLoader(gojsonschema.NewBytesLoader(schema))
}

// NewFromString compiles a JSON Schema given as a JSON string.
func NewFromString(schema string) (*Validator, error) {
	return NewFromLoader(gojsonschema.NewStringLoader(schema))
}

// NewFromLoader compiles a JSON Schema from any gojsonschema loader. Use this
// for schemas that live in files or at URLs and use $ref, e.g.
// gojsonschema.NewReferenceLoader("file:///etc/app/schema.json").
func NewFromLoader(loader gojsonschema.JSONLoader) (*Validator, error) {
	s, err := gojsonschema.NewSchema(loader)
	if err != nil {
		return nil, fmt.Errorf("schemavalidate: compile schema: %w", err)
	}
	return &Validator{schema: s}, nil
}

// Validate checks a Go value (maps, slices and scalars, as produced by a
// YAML or JSON decoder) against the schema.
//
// It returns nil when the document is valid and a *ValidationError listing
// every violation when it is not. Any other error means the document could
// not be checked at all (for example a *KeyError for a non-string map key).
func (v *Validator) Validate(doc any) error {
	normalized, err := NormalizeKeys(doc)
	if err != nil {
		return fmt.Errorf("schemavalidate: invalid document: %w", err)
	}
	return v.run(gojsonschema.NewGoLoader(normalized))
}

// ValidateJSON checks a raw JSON document against the schema. Return values
// follow the same rules as Validate.
func (v *Validator) ValidateJSON(doc []byte) error {
	return v.run(gojsonschema.NewBytesLoader(doc))
}

func (v *Validator) run(doc gojsonschema.JSONLoader) error {
	res, err := v.schema.Validate(doc)
	if err != nil {
		return fmt.Errorf("schemavalidate: validate document: %w", err)
	}
	if res.Valid() {
		return nil
	}
	resultErrs := res.Errors()
	ve := &ValidationError{Errors: make([]error, len(resultErrs))}
	for i, re := range resultErrs {
		ve.Errors[i] = &FieldError{
			Field:       re.Field(),
			Type:        re.Type(),
			Description: re.Description(),
			Value:       re.Value(),
		}
	}
	return ve
}

// Validate is a convenience wrapper that compiles schema (a JSON string) and
// validates doc against it in one call. Prefer a Validator when validating
// more than once against the same schema.
func Validate(schema string, doc interface{}) error {
	v, err := NewFromString(schema)
	if err != nil {
		return err
	}
	return v.Validate(doc)
}
