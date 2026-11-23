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

package schemavalidate

import (
	"fmt"
	"strings"
)

// KeyError is returned when a document contains a map key that is not a
// string and therefore cannot be represented in JSON.
type KeyError struct {
	// Path is the dotted/indexed location of the offending map
	// (e.g. "servers[2].tags"). Empty for the top-level map.
	Path string
	// Key is the offending key.
	Key interface{}
}

// Error implements the error interface.
func (e *KeyError) Error() string {
	location := "at top level"
	if e.Path != "" {
		location = "in " + e.Path
	}
	return fmt.Sprintf("non-string key %s: %#v", location, e.Key)
}

// FieldError describes a single schema violation.
type FieldError struct {
	// Field is the location of the offending value as reported by the
	// schema validator, e.g. "(root)" or "server.port".
	Field string
	// Type is the validator's keyword for the failed constraint,
	// e.g. "required", "invalid_type", "number_gte".
	Type string
	// Description is the human-readable explanation of the violation.
	Description string
	// Value is the offending value, if available.
	Value interface{}
}

// Error implements the error interface.
func (e *FieldError) Error() string {
	return e.Field + ": " + e.Description
}

// ValidationError is returned when a document does not conform to a schema.
// Every element of Errors is a *FieldError.
//
// It supports errors.Is / errors.As traversal into the individual violations
// through Unwrap() []error (Go 1.20+).
type ValidationError struct {
	Errors []error
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	switch len(e.Errors) {
	case 0:
		return "schema validation failed"
	case 1:
		return "schema validation failed: " + e.Errors[0].Error()
	}
	msgs := make([]string, len(e.Errors))
	for i, err := range e.Errors {
		msgs[i] = err.Error()
	}
	return fmt.Sprintf("schema validation failed with %d errors: %s", len(e.Errors), strings.Join(msgs, "; "))
}

// Unwrap returns the individual violations.
func (e *ValidationError) Unwrap() []error { return e.Errors }
