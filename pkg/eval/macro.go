/*
 * Copyright 2021-2026 by Nedim Sabic Sabic
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

package eval

import "github.com/rabbitstack/fibratus/pkg/policy"

// MacroStore represents a store of rule macros.
type MacroStore struct {
	macros []*policy.MacroDef
}

// Add adds a macro
func (s *MacroStore) Add(macro *policy.MacroDef) *MacroStore {
	s.macros = append(s.macros, macro)
	return s
}

// List lists macros
func (s *MacroStore) List() []*policy.MacroDef {
	if s == nil {
		return nil
	}

	return s.macros
}

// Get returns the macro by its identifier.
func (s *MacroStore) Get(id policy.MacroID) *policy.MacroDef {
	if s == nil {
		return nil
	}

	for _, m := range s.macros {
		if m.ID == id {
			return m
		}
	}
	return nil
}

// Contains returns returns true is there is already a macro with this ID in the store
func (s *MacroStore) Contains(id string) bool {
	return s.Get(id) != nil
}
