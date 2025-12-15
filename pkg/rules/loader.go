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

package rules

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/rabbitstack/fibratus/pkg/client"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/ruleset"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type opts struct {
	remoteStore        bool
	rulePaths          []string
	macroPaths         []string
	remoteStoreTimeout time.Duration
}

type LoaderOption func(o *opts)

func WithRemoteStore() LoaderOption {
	return func(o *opts) {
		o.remoteStore = true
	}
}

func WithRulePaths(paths ...string) LoaderOption {
	return func(o *opts) {
		o.rulePaths = paths
	}
}

func WithMacroPaths(paths ...string) LoaderOption {
	return func(o *opts) {
		o.macroPaths = paths
	}
}

func WithRemoteStoreTimeout(timeout time.Duration) LoaderOption {
	return func(o *opts) {
		o.remoteStoreTimeout = timeout
	}
}

type Loader struct {
	// client represents the remote client for communicating with the server
	client client.Client

	subs []ruleset.Subscriber
	mu   sync.Mutex

	// resultq channel is where ruleset compile results are pushed
	resultq chan<- *ruleset.CompileResult
	cerrq   chan<- error
	// rulesetq channel receives ruleset responses from the server
	rulesetq <-chan *ruleset.RuleSet
	errq     <-chan error
}

func NewLoader() *Loader {
	return &Loader{
		subs:     make([]ruleset.Subscriber, 0),
		resultq:  make(chan *ruleset.CompileResult, 10),
		cerrq:    make(chan error),
		rulesetq: make(chan *ruleset.RuleSet),
		errq:     make(chan error),
	}
}

func NewLoaderWithClient(client client.Client) *Loader {
	return &Loader{
		client:   client,
		subs:     make([]ruleset.Subscriber, 0),
		resultq:  make(chan *ruleset.CompileResult, 10),
		cerrq:    make(chan error),
		rulesetq: make(chan *ruleset.RuleSet),
		errq:     make(chan error),
	}
}

func (l *Loader) Load(ctx context.Context, options ...LoaderOption) (*ruleset.RuleSet, error) {
	var opts opts

	for _, opt := range options {
		opt(&opts)
	}

	if opts.remoteStoreTimeout == 0 {
		opts.remoteStoreTimeout = time.Minute * 15
	}

	if opts.remoteStore && l.client != nil {
		l.rulesetq, l.errq = l.client.WatchRules(ctx)
		go l.subscribe(ctx)
		ctx, cancel := context.WithTimeout(ctx, opts.remoteStoreTimeout)
		defer cancel()
		return l.client.ListRules(ctx, &client.RuleListOptions{WithBackoff: true, MaxBackoff: opts.remoteStoreTimeout})
	}

	return l.loadFromFS(opts)
}

func (l *Loader) RegisterSubscriber(subscriber ruleset.Subscriber) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.subs = append(l.subs, subscriber)
}

// subscribe watches for ruleset requests from the provided channel
// and attempts to recompile the rule set. If the rule compilation
// succeeds, the compile result is sent over the channel. Otherwise,
// the error is pushed to the channel.
func (l *Loader) subscribe(ctx context.Context) {
	for {
		select {
		case rs := <-l.rulesetq:
			l.mu.Lock()
			for _, sub := range l.subs {
				log.Infof("recompiling ruleset...")
				res, err := sub.Compile(rs)
				if err != nil {
					l.cerrq <- err
					continue
				}
				select {
				case l.resultq <- res:
				default:
				}
			}
			l.mu.Unlock()
		case err := <-l.errq:
			if err != nil {
				log.Error(err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// loadFromFS loads macros and rules from the local YAML files
// and builds the rule set.
// The Go templates are applied on each macro/rule file before
// running the YAML decoder on them.
func (l *Loader) loadFromFS(opts opts) (*ruleset.RuleSet, error) {
	var (
		rs  = ruleset.New()
		ids = make(map[string]bool)
	)

	if err := l.globPaths(opts.macroPaths, func(path string) error {
		log.Infof("loading macros from file %s", path)
		buf, err := l.loadFromYAML(path, true)
		if err != nil {
			return err
		}
		return unmarshalMacros(buf, rs)
	}); err != nil {
		return nil, err
	}

	if err := l.globPaths(opts.rulePaths, func(path string) error {
		log.Infof("loading rule from %s", path)
		buf, err := l.loadFromYAML(path, false)
		if err != nil {
			return err
		}
		rule, err := unmarshalRule(buf, rs)
		if err != nil {
			return err
		}

		checkDuplicateID := func() error {
			if ids[rule.ID] {
				return fmt.Errorf("%q rule uses duplicate id %s", rule.Name, rule.ID)
			}
			ids[rule.ID] = true
			return nil
		}

		return checkDuplicateID()
	}); err != nil {
		return nil, err
	}

	return rs, nil
}

func isValidExt(path string) bool {
	return filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".yaml"
}

func unmarshalMacros(b []byte, rs *ruleset.RuleSet) error {
	var macros []ruleset.Macro
	if err := yaml.Unmarshal(b, &macros); err != nil {
		return err
	}
	rs.AddMacros(macros...)
	return nil
}

func unmarshalRule(b []byte, rs *ruleset.RuleSet) (*ruleset.Rule, error) {
	var rule ruleset.Rule
	if err := yaml.Unmarshal(b, &rule); err != nil {
		return nil, err
	}
	// explicitly set the type to behaviour rule
	rule.Type = ruleset.BehaviourRule
	rs.AddRule(&rule)
	return &rule, nil
}

func (l *Loader) globPaths(paths []string, f func(string) error) error {
	for _, p := range paths {
		globs, err := filepath.Glob(p)
		if err != nil {
			return err
		}
		for _, path := range globs {
			if !isValidExt(path) {
				continue
			}
			if err := f(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func (l *Loader) loadFromYAML(path string, isMacro bool) ([]byte, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("couldn't load resource from file: %v", err)
	}
	var out interface{}
	if err := yaml.Unmarshal(buf, &out); err != nil {
		return nil, fmt.Errorf("%q is an invalid yaml file: %v", path, err)
	}
	switch isMacro {
	case true:
		// apply validation to macro definition
		if err := config.ValidateMacroSchema(path, out); err != nil {
			return nil, err
		}
	case false:
		// apply validation to rule definition
		if err := config.ValidateRuleSchema(path, out); err != nil {
			return nil, err
		}
	}
	// render template
	return renderTmpl(path, buf)
}

// renderTmpl executes templating directives in the
// rule yaml file. It returns the byte slice
// with yaml content after template expansion.
func renderTmpl(filename string, b []byte) ([]byte, error) {
	tmpl, err := template.New(filename).Funcs(sprig.FuncMap()).Parse(string(b))
	if err != nil {
		return nil, cleanupParseError(filename, err)
	}
	var w bytes.Buffer
	// force strict keys presence
	tmpl.Option("missingkey=error")
	err = tmpl.Execute(&w, nil)
	if err != nil {
		return nil, cleanupParseError(filename, err)
	}
	return w.Bytes(), nil
}

func cleanupParseError(filename string, err error) error {
	if err == nil {
		return nil
	}
	tokens := strings.Split(err.Error(), ": ")
	if len(tokens) < 2 {
		// This might happen if a non-templating error occurs
		return fmt.Errorf("syntax error in (%s): %s", filename, err)
	}
	// The first token is "template"
	// The second token is either "filename:lineno" or "filename:lineNo:columnNo"
	location := tokens[1]
	key := tokens[2]
	i := strings.Index(key, "at")
	if i > 0 {
		key = key[i+3:]
	}
	var errMsg string
	if len(tokens) > 4 {
		errMsg = strings.Join(tokens[3:], ": ")
	} else {
		errMsg = tokens[len(tokens)-1]
	}
	return fmt.Errorf("syntax error in (%s) at %s: %s", location, key, errMsg)
}
