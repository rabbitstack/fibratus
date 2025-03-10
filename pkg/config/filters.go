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
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/util/convert"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"io"
	"net"
	"net/http"
	u "net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/template"
)

// FilterConfig is the descriptor of a single filter.
type FilterConfig struct {
	ID               string            `json:"id" yaml:"id"`
	Name             string            `json:"name" yaml:"name"`
	Description      string            `json:"description" yaml:"description"`
	Version          string            `json:"version" yaml:"version"`
	Condition        string            `json:"condition" yaml:"condition"`
	Action           []FilterAction    `json:"action" yaml:"action"`
	Output           string            `json:"output" yaml:"output"`
	Severity         string            `json:"severity" yaml:"severity"`
	Labels           map[string]string `json:"labels" yaml:"labels"`
	Tags             []string          `json:"tags" yaml:"tags"`
	References       []string          `json:"references" yaml:"references"`
	Notes            string            `json:"notes" yaml:"notes"`
	MinEngineVersion string            `json:"min-engine-version" yaml:"min-engine-version"`
	Enabled          *bool             `json:"enabled" yaml:"enabled"`
}

// FilterAction wraps all possible filter actions.
type FilterAction any

// KillAction defines an action for killing the process
// indicates by the filter field expression.
type KillAction struct{}

// IsolateAction defines an action for isolating the host
// via firewall rules.
type IsolateAction struct {
	// Whitelist contains IP addresses that should remain accessible.
	Whitelist []net.IP `mapstructure:"whitelist"`
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
		case "isolate":
			var isolate IsolateAction
			if err := dec(m, isolate); err != nil {
				return nil, err
			}
		}
	}

	return actions, nil
}

// IsDisabled determines if this filter is disabled.
func (f FilterConfig) IsDisabled() bool { return f.Enabled != nil && !*f.Enabled }

// HasLabel determines if the filter has the given label.
func (f FilterConfig) HasLabel(l string) bool { return f.Labels[l] != "" }

// Filters contains references to rule and macro definitions.
type Filters struct {
	Rules  Rules  `json:"rules" yaml:"rules"`
	Macros Macros `json:"macros" yaml:"macros"`
	// MatchAll indicates if the match all strategy is enabled for the rule engine.
	// If the match all strategy is enabled, a single event can trigger multiple rules.
	MatchAll bool `json:"match-all" yaml:"match-all"`
	macros   map[string]*Macro
	filters  []*FilterConfig
}

// FiltersWithMacros builds the filter config with the map of
// predefined macros. Only used for testing purposes.
func FiltersWithMacros(macros map[string]*Macro) *Filters {
	return &Filters{macros: macros, filters: make([]*FilterConfig, 0)}
}

// Rules contains attributes that describe the location of
// rule resources.
type Rules struct {
	Enabled   bool     `json:"enabled" yaml:"enabled"`
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
// matched filter along with filter information.
type ActionContext struct {
	// Events contains a single element simple rules
	// or a list of ordered matched events for sequence
	// policies
	Events []*kevent.Kevent
	// Filter represents the filter that matched the event
	Filter *FilterConfig
}

// UniquePids returns a set of process identifiers
// from each matched event to be used in actions
// such as the process kill action.
func (ctx *ActionContext) UniquePids() []uint32 {
	pids := make(map[uint32]struct{})
	for _, e := range ctx.Events {
		if e.IsCreateProcess() {
			pids[e.Kparams.MustGetPid()] = struct{}{}
		} else {
			pids[e.PID] = struct{}{}
		}
	}
	return convert.MapKeysToSlice(pids)
}

// RulesCompileResult contains the stats of the
// compiled ruleset, like which event types or
// categories are used. This information permits
// enabling/disabling event providers/types
// dynamically.
type RulesCompileResult struct {
	HasProcEvents       bool
	HasThreadEvents     bool
	HasImageEvents      bool
	HasFileEvents       bool
	HasNetworkEvents    bool
	HasRegistryEvents   bool
	HasHandleEvents     bool
	HasMemEvents        bool
	HasVAMapEvents      bool
	HasDNSEvents        bool
	HasAuditAPIEvents   bool
	HasThreadpoolEvents bool
	UsedEvents          []ktypes.Ktype
	NumberRules         int
}

func (r RulesCompileResult) ContainsEvent(ktype ktypes.Ktype) bool {
	for _, ktyp := range r.UsedEvents {
		if ktyp == ktype {
			return true
		}
	}
	return false
}

func (r RulesCompileResult) String() string {
	m := map[string]bool{}
	events := make([]string, 0)
	for _, ktyp := range r.UsedEvents {
		if m[ktyp.String()] {
			continue
		}
		events = append(events, ktyp.String())
		m[ktyp.String()] = true
	}
	slices.Sort(events)
	return fmt.Sprintf(`
		HasProcEvents: %t
		HasThreadEvents: %t
		HasImageEvents: %t
		HasFileEvents: %t
		HasRegistryEvents: %t
		HasNetworkEvents: %t
		HasHandleEvents: %t
		HasMemEvents: %t
		HasVAMapEvents: %t
		HasAuditAPIEvents: %t
		HasDNSEvents: %t
		HasThreadpoolEvents: %t
		Events: %s`,
		r.HasProcEvents,
		r.HasThreadEvents,
		r.HasImageEvents,
		r.HasFileEvents,
		r.HasRegistryEvents,
		r.HasNetworkEvents,
		r.HasHandleEvents,
		r.HasMemEvents,
		r.HasVAMapEvents,
		r.HasAuditAPIEvents,
		r.HasDNSEvents,
		r.HasThreadpoolEvents,
		strings.Join(events, ", "),
	)
}

const (
	rulesEnabled    = "filters.rules.enabled"
	rulesFromPaths  = "filters.rules.from-paths"
	rulesFromURLs   = "filters.rules.from-urls"
	macrosFromPaths = "filters.macros.from-paths"
	matchAll        = "filters.match-all"
)

func (f *Filters) initFromViper(v *viper.Viper) {
	f.Rules.Enabled = v.GetBool(rulesEnabled)
	f.Rules.FromPaths = v.GetStringSlice(rulesFromPaths)
	f.Rules.FromURLs = v.GetStringSlice(rulesFromURLs)
	f.Macros.FromPaths = v.GetStringSlice(macrosFromPaths)
	f.MatchAll = v.GetBool(matchAll)
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

// LoadFilters loads rules from YAML files or URL addresses.
func (f *Filters) LoadFilters() error {
	f.filters = make([]*FilterConfig, 0)
	ids := make(map[string]bool)

	for _, p := range f.Rules.FromPaths {
		paths, err := filepath.Glob(p)
		if err != nil {
			return err
		}
		for _, path := range paths {
			if !isValidExt(path) {
				continue
			}
			log.Infof("loading rule from %s", path)
			// read the rule file and decode to filter config
			rawConfig, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("couldn't load rule file: %s: %v", path, err)
			}
			flt, err := decodeFilter(path, rawConfig)
			if err != nil {
				return err
			}
			if ids[flt.ID] {
				return fmt.Errorf("%q rule uses duplicate id %s", flt.Name, flt.ID)
			}
			ids[flt.ID] = true
			f.filters = append(f.filters, flt)
		}
	}
	for _, url := range f.Rules.FromURLs {
		log.Infof("loading rule from URL %s", url)
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
		flt, err := decodeFilter(url, rawConfig.Bytes())
		if err != nil {
			return err
		}
		if ids[flt.ID] {
			return fmt.Errorf("%q rule uses duplicate id %s", flt.Name, flt.ID)
		}
		ids[flt.ID] = true
		f.filters = append(f.filters, flt)
	}

	if len(f.filters) == 0 {
		log.Warnf("no rules were loaded from [%s] path(s)", strings.Join(f.Rules.FromPaths, ","))
	}

	return nil
}

func decodeFilter(resource string, b []byte) (*FilterConfig, error) {
	var out interface{}
	err := yaml.Unmarshal(b, &out)
	if err != nil {
		return nil, fmt.Errorf("%q is an invalid yaml file: %v", resource, err)
	}
	// apply validation to rule definition
	valid, errs := validate(rulesSchema, out)
	if !valid || len(errs) > 0 {
		rawRule := out
		b, err := yaml.Marshal(&rawRule)
		if err == nil {
			rawRule = string(b)
		}
		return nil, fmt.Errorf("invalid rule definition: \n\n"+
			"%v in %s: %v", rawRule, resource, multierror.Wrap(errs...))
	}
	// render template
	b, err = renderTmpl(resource, b)
	if err != nil {
		return nil, err
	}
	// now unmarshal into typed filter config
	var flt FilterConfig
	if err := yaml.Unmarshal(b, &flt); err != nil {
		return nil, err
	}
	return &flt, nil
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
