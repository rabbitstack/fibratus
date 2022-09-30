/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package ql

import (
	"github.com/rabbitstack/fibratus/pkg/config"
)

// MacroStore keeps the state of loaded macro definitions
// and provides convenient operations for finding the macros
// in the QL parser.
type MacroStore struct {
	config *config.Config
	macros map[string]*config.Macro
}

// NewMacroStore creates a new macro store by loading
// macros from the file system resources.
func NewMacroStore(c *config.Config) *MacroStore {
	s := &MacroStore{
		config: c,
		macros: make(map[string]*config.Macro),
	}
	return s
}

// NewMacroStoreFromStatic initializes the macro store from static macro definitions.
func NewMacroStoreFromStatic(macros map[string]*config.Macro) *MacroStore {
	s := &MacroStore{
		macros: macros,
	}
	return s
}

// Load loads macro definitions from file system resources.
func (s *MacroStore) Load() error {
	var err error
	s.macros, err = s.config.Filters.LoadMacros()
	if err != nil {
		return err
	}
	return nil
}

// FindMacro returns the macro with the specified identifier.
// If the macro is not found, a nil reference is returned.
func (s MacroStore) FindMacro(id string) *config.Macro {
	return s.macros[id]
}

// IsMacroList determines if the specified macro identifier
// is the list macro.
func (s MacroStore) IsMacroList(id string) bool {
	macro, ok := s.macros[id]
	if !ok {
		return false
	}
	return macro.List != nil
}
