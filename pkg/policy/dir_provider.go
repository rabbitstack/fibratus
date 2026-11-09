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
package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
)

// DirProviderType is the type of the directory provider.
const DirProviderType = "dir"

// defaultDebounce is the quiet period that has to elapse after the last
// file system notification before the provider reports the change. Editors
// and copy operations usually emit several notifications per file.
const defaultDebounce = 500 * time.Millisecond

// watcher stops the underlying file system change notifications.
type watcher interface {
	Close() error
}

// newWatcherFunc builds the watcher for the given directories. The
// notify function is called any time something relevant has changed.
type newWatcherFunc func(dirs []string, notify func()) (watcher, error)

// DirProvider loads policies from YAML files that reside in the local
// file system. Rule and macro paths are glob expressions. Every matching
// file results in a behaviour policy. Rule files hold a single rule, while
// macro files hold a list of macros. On Windows, the directories are
// watched for changes through the directory change notification API.
type DirProvider struct {
	rulePaths  []string
	macroPaths []string

	debounce   time.Duration
	newWatcher newWatcherFunc

	mu     sync.Mutex
	cb     func()
	w      watcher
	timer  *time.Timer
	closed bool
}

// NewDirProvider creates the provider that loads rules and macros from
// the given glob expressions.
func NewDirProvider(rulePaths, macroPaths []string) *DirProvider {
	return &DirProvider{
		rulePaths:  rulePaths,
		macroPaths: macroPaths,
		debounce:   defaultDebounce,
		newWatcher: newDirWatcher,
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

// Load decodes policies from all rule and macro files. Files that fail to
// decode are reported in the returned error, but they don't prevent the
// remaining files from being loaded.
func (p *DirProvider) LoadPolicies() ([]*Policy, error) {
	var (
		policies []*Policy
		errs     []error
	)

	// // macro files go first, so a path that matches both
	// // the macro and rule patterns is treated as a macro file
	// macroFiles, err := p.files(p.macroPaths, seen)
	// if err != nil {
	// 	errs = append(errs, err)
	// }
	// for _, path := range macroFiles {
	// 	log.Infof("loading macros from file %s", path)
	// 	b, err := os.ReadFile(path)
	// 	if err != nil {
	// 		errs = append(errs, fmt.Errorf("couldn't load macros from file: %v", err))
	// 		continue
	// 	}
	// 	macros, err := DecodeMacros(path, b)
	// 	if err != nil {
	// 		errs = append(errs, err)
	// 		continue
	// 	}
	// 	pol := newFilePolicy(path)
	// 	pol.Macros = macros
	// 	policies = append(policies, pol)
	// }

	// ruleFiles, err := p.files(p.rulePaths, seen)
	// if err != nil {
	// 	errs = append(errs, err)
	// }
	// var nrules int
	// for _, path := range ruleFiles {
	// 	log.Infof("loading rule from %s", path)
	// 	b, err := os.ReadFile(path)
	// 	if err != nil {
	// 		errs = append(errs, fmt.Errorf("couldn't load rule file: %s: %v", path, err))
	// 		continue
	// 	}
	// 	rule, err := DecodeRule(path, b)
	// 	if err != nil {
	// 		errs = append(errs, err)
	// 		continue
	// 	}
	// 	pol := newFilePolicy(path)
	// 	pol.Name = rule.Name
	// 	pol.Version = rule.Version
	// 	pol.Description = rule.Description
	// 	pol.Rules = []*RuleDef{rule}
	// 	policies = append(policies, pol)
	// 	nrules++
	// }

	// if nrules == 0 && len(errs) == 0 {
	// 	log.Warnf("no rules were loaded from [%s] path(s)", strings.Join(p.rulePaths, ","))
	// }

	return policies, multierror.Wrap(errs...)
}

func newFilePolicy(path string) *Policy {
	return &Policy{
		ID:           ID(path),
		Name:         strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		Type:         Behaviour,
		InternalType: YAMLInternalType,
		Source:       path,
	}
}

// files expands glob expressions to YAML file paths that were not yet seen.
func (p *DirProvider) files(patterns []string, seen map[string]struct{}) ([]string, error) {
	var (
		files []string
		errs  []error
	)
	for _, pattern := range patterns {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid path pattern %q: %v", pattern, err))
			continue
		}
		for _, path := range paths {
			if !isValidExt(path) {
				continue
			}
			if fi, err := os.Stat(path); err != nil || fi.IsDir() {
				continue
			}
			files = append(files, path)
		}
	}
	return files, multierror.Wrap(errs...)
}

func isValidExt(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".yml" || ext == ".yaml"
}

// watchDirs returns the existing directories that have to be watched
// to detect changes in files matched by the glob expressions.
func watchDirs(patterns ...[]string) []string {
	var dirs []string
	seen := make(map[string]struct{})
	for _, ps := range patterns {
		for _, pattern := range ps {
			dir := filepath.Dir(pattern)
			// climb up until we hit the directory with no glob meta characters
			for strings.ContainsAny(dir, "*?[") {
				parent := filepath.Dir(dir)
				if parent == dir {
					break
				}
				dir = parent
			}
			if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
				log.Warnf("cannot watch %s for policy changes: directory doesn't exist", dir)
				continue
			}
			key := strings.ToLower(filepath.Clean(dir))
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// Start starts watching the rule and macro directories.
func (p *DirProvider) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.w != nil || p.closed {
		return nil
	}
	dirs := watchDirs(p.rulePaths, p.macroPaths)
	if len(dirs) == 0 {
		return nil
	}
	w, err := p.newWatcher(dirs, p.notify)
	if err != nil {
		return fmt.Errorf("unable to watch policy directories: %v", err)
	}
	p.w = w
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
