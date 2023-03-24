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
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"sort"
)

// FieldInfo is the field metadata descriptor.
type FieldInfo struct {
	Field       Field
	Desc        string
	Type        kparams.Type
	Examples    []string
	Deprecation *Deprecation
}

// IsDeprecated determines if the field is deprecated.
func (f FieldInfo) IsDeprecated() bool { return f.Deprecation != nil }

// Deprecation specifies field deprecation info.
type Deprecation struct {
	// Since denotes from which version the field is flagged as deprecated
	Since string
	// Field represents the field by which the deprecated field is superseded
	Field Field
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
