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
	"time"

	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/va"
	log "github.com/sirupsen/logrus"
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

// ExportsDirectoryCache stores the cached module exports extracted
// from the PE export directory.
type ExportsDirectoryCache struct {
	sync.RWMutex
	exports map[string]*ModuleExports

	purger *time.Ticker
	quit   chan struct{}

	psnap ps.Snapshotter
}

// NewExportsDirectoryCache returns a fresh instance of the exports directory cache.
func NewExportsDirectoryCache(psnap ps.Snapshotter) *ExportsDirectoryCache {
	c := &ExportsDirectoryCache{
		exports: make(map[string]*ModuleExports),
		purger:  time.NewTicker(time.Minute * 20),
		quit:    make(chan struct{}, 1),
		psnap:   psnap,
	}
	return c
}

// Exports returns the exports for the given module path. If
// the exports can't be find, then the module PE is parsed
// and the exports cache updated.
func (c *ExportsDirectoryCache) Exports(mod string) (*ModuleExports, bool) {
	c.RLock()
	exports, ok := c.exports[mod]
	c.RUnlock()
	if ok {
		return exports, true
	}
	pe, err := parsePeFile(mod)
	if err != nil {
		return nil, false
	}
	c.Lock()
	defer c.Unlock()
	exports = &ModuleExports{exps: pe.Exports}
	c.exports[mod] = exports
	return exports, true
}

// Clear removes all module exports from the directory cache.
func (c *ExportsDirectoryCache) Clear() {
	c.Lock()
	defer c.Unlock()
	c.exports = make(map[string]*ModuleExports)
}

// RemoveExports removes all exports associated with the module.
func (c *ExportsDirectoryCache) RemoveExports(mod string) {
	c.Lock()
	defer c.Unlock()
	delete(c.exports, mod)
}

func (c *ExportsDirectoryCache) purge() {
	for {
		select {
		case <-c.purger.C:
			c.clearExports()
		case <-c.quit:
			return
		}
	}
}

// clearExports purges all module exports that
// don't exist in the global snapshotter state.
func (c *ExportsDirectoryCache) clearExports() {
	mods := c.psnap.FindAllModules()
	c.Lock()
	defer c.Unlock()
	for exp := range c.exports {
		if _, ok := mods[exp]; !ok {
			log.Debugf("removing stale export %s from directory cache", exp)
			delete(c.exports, exp)
		}
	}
}
