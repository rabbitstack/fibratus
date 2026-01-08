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

package symbolize

import (
	"sync"

	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// ModuleExports contains exports for the specific module
// indexed by RVA (Relative Virtual Address).
type ModuleExports struct {
	exps map[uint32]string
}

// SymbolFromRVA finds the closest export address before RVA.
func (m *ModuleExports) SymbolFromRVA(rva va.Address) string {
	var exp uint32
	for f := range m.exps {
		if uint64(f) <= rva.Uint64() {
			if exp < f {
				exp = f
			}
		}
	}
	if exp != 0 {
		sym, ok := m.exps[exp]
		if ok && sym == "" {
			return "?"
		}
		return sym
	}
	return ""
}

// ExportsCache stores the cached module exports extracted
// from the PE export directory.
type ExportsCache struct {
	sync.RWMutex
	exports map[string]*ModuleExports
}

// NewExportsCache returns a fresh instance of the exports.
func NewExportsCache() *ExportsCache {
	c := &ExportsCache{exports: make(map[string]*ModuleExports)}
	go c.prune()
	return c
}

// Exports returns the exports for the given module path. If
// the exports can't be find, then the module PE is parsed
// and the exports cache updated.
func (e *ExportsCache) Exports(mod string) (*ModuleExports, bool) {
	e.RLock()
	exports, ok := e.exports[mod]
	e.RUnlock()
	if ok {
		return exports, true
	}
	pe, err := parsePeFile(mod)
	if err != nil {
		return nil, false
	}
	e.Lock()
	defer e.Unlock()
	exports = &ModuleExports{exps: pe.Exports}
	e.exports[mod] = exports
	return exports, true
}

// Clear removes all module exports from the cache.
func (e *ExportsCache) Clear() {
	e.Lock()
	defer e.Unlock()
	e.exports = make(map[string]*ModuleExports)
}

func (e *ExportsCache) prune() {

}
