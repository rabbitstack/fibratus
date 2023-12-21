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

package config

import (
	"bytes"
	"fmt"
	"github.com/Masterminds/sprig/v3"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/util/hashers"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"io"
	"net/http"
	u "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

// FilterConfig is the descriptor of a single filter.
type FilterConfig struct {
	Name             string            `json:"name" yaml:"name"`
	Description      string            `json:"description" yaml:"description"`
	Condition        string            `json:"condition" yaml:"condition"`
	Action           []FilterAction    `json:"action" yaml:"action"`
	Output           string            `json:"output" yaml:"output"`
	Severity         string            `json:"severity" yaml:"severity"`
	Labels           map[string]string `json:"labels" yaml:"labels"`
	MinEngineVersion string            `json:"min-engine-version" yaml:"min-engine-version"`
}

// FilterGroup represents the container for filters.
type FilterGroup struct {
	Name        string            `json:"group" yaml:"group"`
	Description string            `json:"description" yaml:"description"`
	Enabled     *bool             `json:"enabled" yaml:"enabled"`
	Rules       []*FilterConfig   `json:"rules" yaml:"rules"`
	Tags        []string          `json:"tags" yaml:"tags"`
	Labels      map[string]string `json:"labels" yaml:"labels"`
}

// FilterAction wraps all possible filter actions.
type FilterAction any

// KillAction defines an action for killing the process
// indicates by the filter field expression.
type KillAction struct {
	// Pid indicates the field for which
	// the process id is resolved
	Pid string `json:"pid" yaml:"pid"`
}

func (a KillAction) PidToInt(pid string) uint32 {
	n, err := strconv.Atoi(pid)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// DecodeActions converts raw YAML map to
// typed action structures.
func (f FilterConfig) DecodeActions() ([]any, error) {
	actions := make([]any, 0, len(f.Action))

	dec := func(m map[string]any, o any) error {
		err := decode(m, &o)
		if err != nil {
			return err
		}
		actions = append(actions, o)
		return nil
	}

	for _, act := range f.Action {
		m, ok := act.(map[string]any)
		if !ok {
			continue
		}
		switch m["name"] {
		case "kill":
			var kill KillAction
			if err := dec(m, kill); err != nil {
				return nil, err
			}
		}
	}
	return actions, nil
}

// IsDisabled determines if this group is disabled.
func (g FilterGroup) IsDisabled() bool { return g.Enabled != nil && !*g.Enabled }

// Hash calculates the filter group hash.
func (g FilterGroup) Hash() uint32 {
	return hashers.FnvUint32([]byte(g.Name))
}

// Filters contains references to rule groups and macro definitions.
// Each filter group can contain multiple filter expressions which
// represent the rules.
type Filters struct {
	Rules  Rules  `json:"rules" yaml:"rules"`
	Macros Macros `json:"macros" yaml:"macros"`
	macros map[string]*Macro
	groups []FilterGroup
}

// FiltersWithMacros builds the filter config with the map of
// predefined macros. Only used for testing purposes.
func FiltersWithMacros(macros map[string]*Macro) *Filters {
	return &Filters{macros: macros, groups: make([]FilterGroup, 0)}
}

// Rules contains attributes that describe the location of
// rule resources.
type Rules struct {
	FromPaths []string `json:"from-paths" yaml:"from-paths"`
	FromURLs  []string `json:"from-urls" yaml:"from-urls"`
}

// Macros contains attributes that describe the location of
// macro resources.
type Macros struct {
	FromPaths []string `json:"from-paths" yaml:"from-paths"`
}

// Macro represents the state of the rule macro. Macros
// either expand to expressions or lists.
type Macro struct {
	ID          string   `json:"macro" yaml:"macro"`
	Description string   `json:"description" yaml:"description"`
	Expr        string   `json:"expr" yaml:"expr"`
	List        []string `json:"list" yaml:"list"`
}

// ActionContext is the convenient structure
// for grouping the event that resulted in
// matched filter along with filter group
// information.
type ActionContext struct {
	// Events contains a single element for non-sequence
	// group policies or a list of ordered matched events
	// for sequence group policies
	Events []*kevent.Kevent
	// Filter represents the filter that matched the event
	Filter *FilterConfig
	// Group represents the group where the filter is declared
	Group FilterGroup
}

const (
	rulesFromPaths  = "filters.rules.from-paths"
	rulesFromURLs   = "filters.rules.from-urls"
	macrosFromPaths = "filters.macros.from-paths"
)

func (f *Filters) initFromViper(v *viper.Viper) {
	f.Rules.FromPaths = v.GetStringSlice(rulesFromPaths)
	f.Rules.FromURLs = v.GetStringSlice(rulesFromURLs)
	f.Macros.FromPaths = v.GetStringSlice(macrosFromPaths)
}

func (f Filters) HasMacros() bool           { return len(f.macros) > 0 }
func (f Filters) GetMacro(id string) *Macro { return f.macros[id] }
func (f Filters) IsMacroList(id string) bool {
	macro, ok := f.macros[id]
	if !ok {
		return false
	}
	return macro.List != nil
}

// LoadMacros from the macro library. The Go templates are applied
// on each macro file before running the YAML decoder on them.
func (f *Filters) LoadMacros() error {
	f.macros = make(map[string]*Macro)
	for _, p := range f.Macros.FromPaths {
		paths, err := filepath.Glob(p)
		if err != nil {
			return err
		}
		for _, path := range paths {
			if !isValidExt(path) {
				continue
			}
			log.Infof("loading macros from file %s", path)
			buf, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("couldn't load macros from file: %v", err)
			}
			// validate macro yaml structure
			var out interface{}
			err = yaml.Unmarshal(buf, &out)
			if err != nil {
				return fmt.Errorf("%q is invalid macro yaml file: %v", path, err)
			}
			valid, errs := validate(macrosSchema, out)
			if !valid || len(errs) > 0 {
				b, err := yaml.Marshal(&out)
				if err == nil {
					out = string(b)
				}
				return fmt.Errorf("invalid macro definition: \n\n"+
					"%v in %s: %v", out, path, multierror.Wrap(errs...))
			}
			buf, err = renderTmpl(path, buf)
			if err != nil {
				return err
			}
			// unmarshal macros and transform to map
			var macros []Macro
			if err := yaml.Unmarshal(buf, &macros); err != nil {
				return err
			}
			for _, m := range macros {
				f.macros[m.ID] = &Macro{
					ID:          m.ID,
					Description: m.Description,
					Expr:        m.Expr,
					List:        m.List,
				}
			}
		}
	}
	return nil
}

func isValidExt(path string) bool {
	return filepath.Ext(path) == ".yml" || filepath.Ext(path) == ".yaml"
}

// LoadGroups for each rule group file it decodes the
// groups and ensures the correctness of the yaml file.
func (f *Filters) LoadGroups() error {
	f.groups = make([]FilterGroup, 0)
	for _, p := range f.Rules.FromPaths {
		paths, err := filepath.Glob(p)
		if err != nil {
			return err
		}
		for _, path := range paths {
			if !isValidExt(path) {
				continue
			}
			log.Infof("loading rules from file %s", path)
			// read the file group yaml file and produce
			// the corresponding filter groups from it
			rawConfig, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("couldn't load rule file: %v", err)
			}
			groups, err := decodeFilterGroups(path, rawConfig)
			if err != nil {
				return err
			}
			f.groups = append(f.groups, groups...)
		}
	}
	for _, url := range f.Rules.FromURLs {
		log.Infof("loading rules from URL %s", url)
		if _, err := u.Parse(url); err != nil {
			return fmt.Errorf("%q is an invalid URL", url)
		}
		//nolint:noctx
		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("cannot fetch rule file from %q: %v", url, err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return fmt.Errorf("got non-ok status code for %q: %s", url,
				http.StatusText(resp.StatusCode))
		}

		var rawConfig bytes.Buffer
		_, err = io.Copy(&rawConfig, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return fmt.Errorf("cannot copy rule file from %q: %v", url, err)
		}
		groups, err := decodeFilterGroups(url, rawConfig.Bytes())
		if err != nil {
			return err
		}
		f.groups = append(f.groups, groups...)
	}

	// check for duplicate rule groups
	groupNames := make(map[string]bool)
	for _, group := range f.groups {
		_, isDup := groupNames[group.Name]
		if isDup {
			return fmt.Errorf("group names must be unique. "+
				"Found duplicate %q group", group.Name)
		}
		groupNames[group.Name] = true
	}
	return nil
}

func decodeFilterGroups(resource string, b []byte) ([]FilterGroup, error) {
	var out interface{}
	err := yaml.Unmarshal(b, &out)
	if err != nil {
		return nil, fmt.Errorf("%q is invalid yaml file: %v", resource, err)
	}
	rawGroups, ok := out.([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid rule group "+
			"file %s: expected array(s) of groups", resource)
	}
	// apply validation to each group
	// declared in the yml config file
	for _, group := range rawGroups {
		valid, errs := validate(rulesSchema, group)
		if !valid || len(errs) > 0 {
			rawGroup := group
			b, err := yaml.Marshal(&rawGroup)
			if err == nil {
				rawGroup = string(b)
			}
			return nil, fmt.Errorf("invalid rule group: \n\n"+
				"%v in %s: %v", rawGroup, resource, multierror.Wrap(errs...))
		}
	}
	// render template
	b, err = renderTmpl(resource, b)
	if err != nil {
		return nil, err
	}
	// now unmarshal into typed group slice
	var groups []FilterGroup
	if err := yaml.Unmarshal(b, &groups); err != nil {
		return nil, err
	}
	return groups, nil
}

// renderTmpl executes templating directives in the
// file group yaml file. It returns the byte slice
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
