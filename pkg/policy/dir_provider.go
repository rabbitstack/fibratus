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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/util/fswatcher"
)

// DirProviderType is the type of the directory provider.
const DirProviderType = "dir"

// defaultDebounce is the quiet period that has to elapse after the last
// file system notification before the provider reports the change. Editors
// and copy operations usually emit several notifications per file.
const defaultDebounce = 500 * time.Millisecond

// DirProvider loads policies from YAML files that reside in the local
// file system. Rule and macro paths are glob expressions. Every matching
// file results in a behaviour policy. Rule files hold a single rule, while
// macro files hold a list of macros. Directories are watched for changes
// through the directory change notification API on Windows and fsnotify on
// Linux platforms.
type DirProvider struct {
	ruleGlobs  []string
	macroGlobs []string

	ruleBundle  *RuleBundle
	macroBundle *MacroBundle

	debounce time.Duration

	mu     sync.Mutex
	cb     func()
	w      *fswatcher.Watcher
	timer  *time.Timer
	closed bool
}

// NewDirProvider creates the provider that loads rules and macros from
// the given glob expressions.
func NewDirProvider(ruleGlobs, macroGlobs []string) *DirProvider {
	return &DirProvider{
		ruleGlobs:   ruleGlobs,
		macroGlobs:  macroGlobs,
		ruleBundle:  NewRuleBundle(),
		macroBundle: NewMacroBundle(),
		debounce:    defaultDebounce,
	}
}

// Type returns the provider type.
func (p *DirProvider) Type() string { return DirProviderType }

// SetOnPoliciesChanged registers the callback invoked when policy files change.
func (p *DirProvider) SetOnPoliciesChanged(cb func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cb = cb
}

// Load decodes the directory policy from all rule and macro files.
func (p *DirProvider) LoadPolicies() ([]*Policy, error) {
	var (
		policies []*Policy
		rules    []*RuleDef
		macros   []*MacroDef
	)

	if err := p.loadIntoBundle(p.ruleBundle, p.ruleGlobs); err != nil {
		return nil, err
	}

	if err := p.loadIntoBundle(p.macroBundle, p.macroGlobs); err != nil {
		return nil, err
	}

	if err := p.ruleBundle.Validate(); err != nil {
		return nil, err
	}

	if err := p.macroBundle.Validate(); err != nil {
		return nil, err
	}

	var err error
	rules, err = p.ruleBundle.Rules()
	if err != nil {
		return nil, err
	}
	macros, err = p.macroBundle.Macros()
	if err != nil {
		return nil, err
	}

	policy := newDirPolicy(YAMLInternalPolicyID)
	policy.Rules = rules
	policy.Macros = macros
	policy.Source = ""

	policies = append(policies, policy)

	return policies, nil
}

func newDirPolicy(id ID) *Policy {
	return &Policy{
		ID:           id,
		Type:         Behaviour,
		InternalType: YAMLInternalType,
	}
}

// Start starts watching the rule and macro directories.
func (p *DirProvider) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.w != nil || p.closed {
		return nil
	}
	// dirs := watchDirs(p.rulePaths, p.macroPaths)
	// if len(dirs) == 0 {
	// 	return nil
	// }

	return nil
}

// notify schedules the change callback. A burst of notifications is
// collapsed into a single callback invocation.
func (p *DirProvider) notify() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	p.timer = time.AfterFunc(p.debounce, p.fire)
}

func (p *DirProvider) fire() {
	p.mu.Lock()
	cb, closed := p.cb, p.closed
	p.mu.Unlock()
	if closed || cb == nil {
		return
	}
	cb()
}

// Close stops watching directories.
func (p *DirProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.timer != nil {
		p.timer.Stop()
	}
	if p.w != nil {
		return p.w.Close()
	}
	return nil
}

// loadIntoBundle loads all matching YAML files into the provided bundle.
// Files are processed in lexical path order. Duplicate paths are ignored.
func (p *DirProvider) loadIntoBundle(bundle YAMLBundleAdder, globs []string) error {
	if bundle == nil {
		return errors.New("YAML bundle cannot be nil")
	}

	files, err := p.files(globs)
	if err != nil {
		return err
	}

	for _, path := range files {
		if err := p.addFile(bundle, path); err != nil {
			return err
		}
	}

	return nil
}

// addFile opens a YAML file, adds its definitions to the bundle,
// and closes the file.
func (*DirProvider) addFile(bundle YAMLBundleAdder, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open YAML file %q: %w", path, err)
	}

	addErr := bundle.AddFrom(path, f)
	closeErr := f.Close()

	if addErr != nil {
		return fmt.Errorf("read YAML file %q: %w", path, addErr)
	}

	if closeErr != nil {
		return fmt.Errorf("close YAML file %q: %w", path, closeErr)
	}

	return nil
}

// files expands all configured glob expressions and returns
// unique YAML file paths in lexical order.
func (p *DirProvider) files(globs []string) ([]string, error) {
	var (
		files []string
		errs  []error
		seen  = make(map[string]struct{})
	)

	for _, pattern := range globs {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"invalid path pattern %q: %w",
				pattern,
				err,
			))
			continue
		}

		for _, path := range paths {
			if !isYAMLFile(path) {
				continue
			}

			info, err := os.Stat(path)
			if err != nil {
				errs = append(errs, fmt.Errorf(
					"stat YAML file %q: %w",
					path,
					err,
				))
				continue
			}

			if !info.Mode().IsRegular() {
				continue
			}

			path = filepath.Clean(path)

			if _, exists := seen[path]; exists {
				continue
			}

			seen[path] = struct{}{}
			files = append(files, path)
		}
	}

	sort.Strings(files)

	return files, errors.Join(errs...)
}

// isYAMLFile reports whether path has a YAML file extension.
func isYAMLFile(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yml", ".yaml":
		return true
	default:
		return false
	}
}
