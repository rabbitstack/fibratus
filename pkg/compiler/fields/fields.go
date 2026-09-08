/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package fields

import (
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"sort"
	"unicode"
)

// FieldInfo is the field metadata descriptor.
type FieldInfo struct {
	Field       Field
	Desc        string
	Type        params.Type
	Examples    []string
	Deprecation *Deprecation
	Argument    *Argument
}

// isNumber is the field argument validation function that
// returns true if all characters are digits.
var isNumber = func(s string) bool {
	for _, c := range s {
		if !unicode.IsNumber(c) {
			return false
		}
	}
	return true
}

// Argument defines field argument information.
type Argument struct {
	// Optional indicates if the argument is optional.
	Optional bool
	// ValidationFunc is the field argument validation function.
	// It returns true if the provided argument is valid, or false
	// otherwise.
	ValidationFunc func(string) bool
	// Pattern contains the regular expression like string that
	// represents the character set allowed for the argument value.
	Pattern string
}

// Validate validates the provided field argument.
func (a *Argument) Validate(v string) bool {
	if a.ValidationFunc == nil {
		return true
	}
	return a.ValidationFunc(v)
}

// IsDeprecated determines if the field is deprecated.
func (f FieldInfo) IsDeprecated() bool { return f.Deprecation != nil }

// Deprecation specifies field deprecation info.
type Deprecation struct {
	// Since denotes from which version the field is flagged as deprecated
	Since string
	// Fields represents the fields by which the deprecated field is superseded
	Fields []Field
}

// Get returns a slice of field information.
func Get() []FieldInfo {
	fi := make([]FieldInfo, 0, len(fields))
	for _, field := range fields {
		fi = append(fi, field)
	}
	sort.Slice(fi, func(i, j int) bool { return fi[i].Field < fi[j].Field })
	return fi
}

// IsDeprecated determines if the given field is deprecated.
func IsDeprecated(f Field) (bool, *Deprecation) {
	for _, field := range fields {
		if field.Field == f && field.IsDeprecated() {
			return true, field.Deprecation
		}
	}
	return false, nil
}

// IsBoolean determines if the given field has the bool type.
func IsBoolean(f Field) bool {
	return fields[f].Type == params.Bool
}
