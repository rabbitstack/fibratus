/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package event

import (
	"cmp"
	"slices"
)

// Info describes an event's human-readable name, category, and purpose.
type Info struct {
	Name        string
	Category    Category
	Description string
}

// GetTypesMeta returns event type metadata without duplicate display names.
func GetTypesMeta() []Info {
	infos := make([]Info, 0, len(events))
outer:
	for _, info := range events {
		for _, existing := range infos {
			if existing.Name == info.Name {
				continue outer
			}
		}
		infos = append(infos, info)
	}
	slices.SortFunc(infos, func(a, b Info) int {
		return cmp.Or(cmp.Compare(a.Category, b.Category), cmp.Compare(a.Name, b.Name))
	})
	return infos
}

// IsKnown reports whether the event name is registered.
func IsKnown(name string) bool {
	return NameToType(name) != UnknownType
}
