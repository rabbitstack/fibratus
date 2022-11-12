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
	"encoding/base64"
	"fmt"
	"github.com/Masterminds/sprig/v3"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"hash/fnv"
	"io"
	"net/http"
	u "net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

// FilterGroupPolicy is the type alias for the filter group policy
type FilterGroupPolicy uint8

// FilterGroupRelation is the type alias for the filter group relation
type FilterGroupRelation uint8

const (
	// IncludePolicy determines the policy type that allows for
	// filtering the matching events.
	IncludePolicy FilterGroupPolicy = iota
	// ExcludePolicy determines the policy that allows for filtering
	// out the matching events, that is, discarding them from the event
	// flow.
	ExcludePolicy
	// SequencePolicy determines the policy that allows matching a
	// sequence of temporal events based on pattern binding restrictions
	SequencePolicy
	// UnknownPolicy determines the unknown group policy type.
	UnknownPolicy
)

const (
	// OrRelation is the group relation type that requires at
	// least one matching filter to evaluate successfully.
	OrRelation FilterGroupRelation = iota
	// AndRelation is the group relation type that requires that
	// all the filters to match in order to evaluate successfully.
	AndRelation
	// UnknownRelation determines the unknown group relation type.
	UnknownRelation
)

// String yields a human-readable group policy.
func (p FilterGroupPolicy) String() string {
	switch p {
	case IncludePolicy:
		return "include"
	case ExcludePolicy:
		return "exclude"
	case SequencePolicy:
		return "sequence"
	default:
		return ""
	}
}

// String yields a human-readable group relation.
func (r FilterGroupRelation) String() string {
	switch r {
	case OrRelation:
		return "or"
	case AndRelation:
		return "and"
	default:
		return ""
	}
}

// UnmarshalYAML converts the policy string to enum type.
func (p *FilterGroupPolicy) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var policy string
	err := unmarshal(&policy)
	if err != nil {
		return err
	}
	*p = filterGroupPolicyFromString(policy)
	return nil
}

// UnmarshalYAML converts the relation string to enum type.
func (r *FilterGroupRelation) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var relation string
	err := unmarshal(&relation)
	if err != nil {
		return err
	}
	*r = filterGroupRelationFromString(relation)
	return nil
}

func filterGroupPolicyFromString(s string) FilterGroupPolicy {
	switch s {
	case "include", "INCLUDE":
		return IncludePolicy
	case "exclude", "EXCLUDE":
		return ExcludePolicy
	case "sequence", "SEQUENCE":
		return SequencePolicy
	default:
		return UnknownPolicy
	}
}

func filterGroupRelationFromString(s string) FilterGroupRelation {
	switch s {
	case "or", "OR":
		return OrRelation
	case "and", "AND":
		return AndRelation
	default:
		return UnknownRelation
	}
}

// FilterConfig is the descriptor of a single filter.
type FilterConfig struct {
	Name        string            `json:"name" yaml:"name"`
	Description string            `json:"description" yaml:"description"`
	Def         string            `json:"def" yaml:"def"` // deprecated in favor of `Condition`
	Condition   string            `json:"condition" yaml:"condition"`
	Action      string            `json:"action" yaml:"action"`
	MaxSpan     time.Duration     `json:"max-span" yaml:"max-span"`
	Labels      map[string]string `json:"labels" yaml:"labels"`
}

// parseTmpl ensures the correctness of the rule
// action template by trying to parse the template
// string from the base64 payload.
func (f FilterConfig) parseTmpl(resource string) error {
	if f.Action == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(f.Action)
	if err != nil {
		return err
	}
	tmpl, err := template.New(f.Name).Funcs(FilterFuncMap()).Parse(string(decoded))
	if err != nil {
		return cleanupParseError(resource, err)
	}
	var bb bytes.Buffer
	return cleanupParseError(resource, tmpl.Execute(&bb, tmplData()))
}

// FilterGroup represents the container for filters.
type FilterGroup struct {
	Name        string              `json:"group" yaml:"group"`
	Description string              `json:"description" yaml:"description"`
	Enabled     *bool               `json:"enabled" yaml:"enabled"`
	Selector    FilterGroupSelector `json:"selector" yaml:"selector"`
	Policy      FilterGroupPolicy   `json:"policy" yaml:"policy"`
	Relation    FilterGroupRelation `json:"relation" yaml:"relation"`
	Rules       []*FilterConfig     `json:"rules" yaml:"rules"`
	FromStrings []*FilterConfig     `json:"from-strings" yaml:"from-strings"` // deprecated in favor or `Rules`
	Tags        []string            `json:"tags" yaml:"tags"`
	Labels      map[string]string   `json:"labels" yaml:"labels"`
	Action      string              `json:"action" yaml:"action"` // only valid in sequence policies
}

// IsDisabled determines if this group is disabled.
func (g FilterGroup) IsDisabled() bool { return g.Enabled != nil && !*g.Enabled }

func (g FilterGroup) validate(resource string) error {
	filters := append(g.FromStrings, g.Rules...)
	for _, filter := range filters {
		if filter.Action != "" && g.Policy == ExcludePolicy {
			return fmt.Errorf("%q rule found in %q group with exclude policy. "+
				"Only groups with include policies can have rule actions", filter.Name, g.Name)
		}
		if filter.MaxSpan != 0 && g.Policy != SequencePolicy {
			return fmt.Errorf("%q rule has max span, but it is not in sequence policy " +
				filter.Name)
		}
		if err := filter.parseTmpl(resource); err != nil {
			return fmt.Errorf("invalid %q rule action: %v", filter.Name, err)
		}
	}
	return nil
}

// Hash calculates the filter group hash.
func (g FilterGroup) Hash() uint32 {
	h := fnv.New32()
	_, err := h.Write([]byte(g.Policy.String() + g.Name))
	if err != nil {
		return 0
	}
	return h.Sum32()
}

// FilterGroupSelector permits specifying the events
// that will be captured by particular filter group.
// Only one of type or category selectors can be active
// at the same time.
type FilterGroupSelector struct {
	Type     ktypes.Ktype    `json:"type" yaml:"type"`
	Category ktypes.Category `json:"category" yaml:"category"`
}

// Hash computes the filter group selector hash.
func (s FilterGroupSelector) Hash() uint32 {
	hash := s.Type.Hash()
	if hash != 0 {
		return hash
	}
	return s.Category.Hash()
}

// Filters contains references to rule groups and macro definitions.
// Each filter group can contain multiple filter expressions whcih
// represent the rules.
type Filters struct {
	Rules  Rules  `json:"rules" yaml:"rules"`
	Macros Macros `json:"macros" yaml:"macros"`
	macros map[string]*Macro
}

// FiltersWithMacros builds the filter config with the map of
// predefined macros. Only used for testing purposes.
func FiltersWithMacros(macros map[string]*Macro) *Filters {
	return &Filters{macros: macros}
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
			if filepath.Ext(path) != ".yml" && filepath.Ext(path) != ".yaml" {
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

// LoadGroups for each rule group file it decodes the
// groups and ensures the correctness of the yaml file.
func (f Filters) LoadGroups() ([]FilterGroup, error) {
	allGroups := make([]FilterGroup, 0)
	for _, p := range f.Rules.FromPaths {
		paths, err := filepath.Glob(p)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			if filepath.Ext(path) != ".yml" && filepath.Ext(path) != ".yaml" {
				continue
			}
			log.Infof("loading rules from file %s", path)
			// read the file group yaml file and produce
			// the corresponding filter groups from it
			rawConfig, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("couldn't load rule file: %v", err)
			}
			groups, err := decodeFilterGroups(path, rawConfig)
			if err != nil {
				return nil, err
			}
			allGroups = append(allGroups, groups...)
		}
	}
	for _, url := range f.Rules.FromURLs {
		log.Infof("loading rules from URL %s", url)
		if _, err := u.Parse(url); err != nil {
			return nil, fmt.Errorf("%q is an invalid URL", url)
		}
		//nolint:noctx
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("cannot fetch rule file from %q: %v", url, err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("got non-ok status code for %q: %s", url,
				http.StatusText(resp.StatusCode))
		}

		var rawConfig bytes.Buffer
		_, err = io.Copy(&rawConfig, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("cannot copy rule file from %q: %v", url, err)
		}
		groups, err := decodeFilterGroups(url, rawConfig.Bytes())
		if err != nil {
			return nil, err
		}
		allGroups = append(allGroups, groups...)
	}
	return allGroups, nil
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
	// convert filter action template to
	// base64 before executing the global
	// template. The rendered template yields
	// a yaml payload with template directives
	// expanded
	b, err = encodeFilterActions(b)
	if err != nil {
		return nil, err
	}
	b, err = renderTmpl(resource, b)
	if err != nil {
		return nil, err
	}

	// now unmarshal into typed group slice
	var groups []FilterGroup
	if err := yaml.Unmarshal(b, &groups); err != nil {
		return nil, err
	}
	// try to validate filter action template
	for _, group := range groups {
		err := group.validate(resource)
		if err != nil {
			return nil, err
		}
	}
	return groups, nil
}

// renderTmpl executes templating directives in the
// file group yaml file. It returns the byte slice
// with yaml content after template expansion.
func renderTmpl(filename string, b []byte) ([]byte, error) {
	tmpl, err := template.New(filename).Funcs(FilterFuncMap()).Parse(string(b))
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

// ActionContext is the convenient structure
// for grouping the event that resulted in
// matched filter along with filter group
// information.
type ActionContext struct {
	Kevt *kevent.Kevent
	// Kevts contains matched events for sequence group
	// policies indexed by `k` + the slot number of the
	// rule that produced a partial match
	Kevts map[string]*kevent.Kevent
	// Events contains a single element for non-sequence
	// group policies or a list of ordered matched events
	// for sequence group policies
	Events []*kevent.Kevent
	Filter *FilterConfig
	Group  FilterGroup
}

// FilterFuncMap returns the template func map
// populated with some useful template functions
// that can be used in rule actions.
func FilterFuncMap() template.FuncMap {
	f := sprig.TxtFuncMap()

	extra := template.FuncMap{
		// This is a placeholder for the functions that might be
		// late-bound to a template. By declaring them here, we
		// can still execute the template associated with the
		// filter action to ensure template syntax is correct
		"emit": func(ctx *ActionContext, title string, text string, args ...string) string { return "" },
		"kill": func(pid uint32) string { return "" },
	}

	for k, v := range extra {
		f[k] = v
	}

	return f
}

func tmplData() *ActionContext {
	return &ActionContext{
		Filter: &FilterConfig{},
		Group:  FilterGroup{},
		Kevt:   kevent.Empty(),
		Events: make([]*kevent.Kevent, 0),
		Kevts:  make(map[string]*kevent.Kevent),
	}
}

const (
	actionNode      = "action"
	defNode         = "def"
	fromStringsNode = "from-strings"
	rulesNode       = "rules"
)

// encodeFilterActions convert the filter action template
// to base64 payload. Because we only want to execute
// the action template when a filter matches in runtime,
// encoding the template to base64 prevents the Go templating
// engine from expanding the template in parse time, when we
// first load all the filter groups.
func encodeFilterActions(buf []byte) ([]byte, error) {
	var yn yaml.Node
	if err := yaml.Unmarshal(buf, &yn); err != nil {
		return nil, err
	}

	// for each group
	for _, n := range yn.Content[0].Content {
		// for each group node
		for i, gn := range n.Content {
			// sequence groups action
			if gn.Value == actionNode && n.Content[i+1].Value != "" {
				n.Content[i+1].Value =
					base64.StdEncoding.EncodeToString([]byte(n.Content[i+1].Value))
			}
			if gn.Value == fromStringsNode {
				log.Warnf("`from-strings` attribute is deprecated and will be " +
					"removed in future versions. Please consider switching to `rules` attribute")
			}
			if gn.Value == fromStringsNode || gn.Value == rulesNode {
				content := n.Content[i+1]
				// for each node in from-strings
				for _, s := range content.Content {
					for j, e := range s.Content {
						if e.Value == defNode {
							log.Warnf("`def` attribute is deprecated and will be " +
								"removed in future versions. Please consider switching to `condition` attribute")
						}
						if e.Value == actionNode && s.Content[j+1].Value != "" {
							s.Content[j+1].Value =
								base64.StdEncoding.EncodeToString([]byte(s.Content[j+1].Value))
						}
					}
				}
			}
		}
	}

	b, err := yaml.Marshal(&yn)
	if err != nil {
		return nil, err
	}
	return b, nil
}
