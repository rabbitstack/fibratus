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
	"github.com/rabbitstack/fibratus/pkg/filter/funcmap"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"io"
	"io/ioutil"
	"net/http"
	u "net/url"
	"os"
	"path/filepath"
	"strings"
	"text/template"
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

// String yields human readable group policy.
func (p FilterGroupPolicy) String() string {
	switch p {
	case IncludePolicy:
		return "include"
	case ExcludePolicy:
		return "exclude"
	default:
		return ""
	}
}

// String yields human readable group relation.
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
	Name   string `json:"name" yaml:"name"`
	Def    string `json:"def" yaml:"def"`
	Action string `json:"action" yaml:"action"`
}

// parseTmpl ensures the correctness of the filter
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
	tmpl, err := template.New(f.Name).Funcs(funcmap.New()).Parse(string(decoded))
	if err != nil {
		return cleanupParseError(resource, err)
	}
	var bb bytes.Buffer
	return cleanupParseError(resource, tmpl.Execute(&bb, tmplData()))
}

// FilterGroup represents the container for filters.
type FilterGroup struct {
	Name        string              `json:"group" yaml:"group"`
	Enabled     bool                `json:"enabled" yaml:"enabled"`
	Selector    FilterGroupSelector `json:"selector" yaml:"selector"`
	Policy      FilterGroupPolicy   `json:"policy" yaml:"policy"`
	Relation    FilterGroupRelation `json:"relation" yaml:"relation"`
	FromStrings []*FilterConfig     `json:"from-strings" yaml:"from-strings"`
	Tags        []string            `json:"tags" yaml:"tags"`
}

func (g FilterGroup) validate(resource string) error {
	for _, filter := range g.FromStrings {
		if filter.Action != "" && g.Policy == ExcludePolicy {
			return fmt.Errorf("%q filter found in %q group with exclude policy. "+
				"Only groups with include policies can have filter actions", filter.Name, g.Name)
		}
		if err := filter.parseTmpl(resource); err != nil {
			return fmt.Errorf("invalid %q filter action: %v", filter.Name, err)
		}
	}
	return nil
}

// FilterGroupSelector permits specifying the events
// that will be captured by particular filter group.
// Only one of type or category selectors can be active
// at the same time.
type FilterGroupSelector struct {
	Type     ktypes.Ktype    `json:"type" yaml:"type"`
	Category ktypes.Category `json:"category" yaml:"category"`
}

// Filters contains references to filter group definitions.
// Each filter group can contain multiple filter expressions.
// Filter expressions can reside in the filter group file or
// live in a separate file.
type Filters struct {
	FromPaths []string `json:"from-paths" yaml:"from-paths"`
	FromURLs  []string `json:"from-urls" yaml:"from-urls"`
}

const filtersFromPaths = "filters.from-paths"
const filtersFromURLs = "filters.from-urls"

func (f *Filters) initFromViper(v *viper.Viper) {
	f.FromPaths = v.GetStringSlice(filtersFromPaths)
	f.FromURLs = v.GetStringSlice(filtersFromURLs)
}

// LoadGroups for each filter group file it decodes the
// groups and ensures the correctness of the yaml file.
func (f Filters) LoadGroups() ([]FilterGroup, error) {
	allGroups := make([]FilterGroup, 0)
	for _, path := range f.FromPaths {
		file, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("couldn't open rule file %s: %v", path, err)
		}
		if file.IsDir() {
			return nil, fmt.Errorf("expected yml file but got directory %s", path)
		}
		// read the file group yaml file and produce
		// the corresponding filter groups from it
		rawConfig, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("couldn't load rule file: %v", err)
		}
		groups, err := decodeFilterGroups(path, rawConfig)
		if err != nil {
			return nil, err
		}
		allGroups = append(allGroups, groups...)
	}
	for _, url := range f.FromURLs {
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
		return nil, fmt.Errorf("invalid filter group "+
			"file %s: expected array(s) of groups", resource)
	}
	// apply validation to each group
	// declared in the yml config file
	for _, group := range rawGroups {
		valid, errs := validate(filterGroupSchema, group)
		if !valid || len(errs) > 0 {
			rawGroup := group
			b, err := yaml.Marshal(&rawGroup)
			if err == nil {
				rawGroup = string(b)
			}
			return nil, fmt.Errorf("invalid filter group: \n\n"+
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
	rawValues, err := unmarshalValues(filename)
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New(filename).Funcs(funcmap.New()).Parse(string(b))
	if err != nil {
		return nil, cleanupParseError(filename, err)
	}
	var w bytes.Buffer
	// force strict keys presence
	tmpl.Option("missingkey=error")
	err = tmpl.Execute(&w, map[string]interface{}{"Values": rawValues})
	if err != nil {
		return nil, cleanupParseError(filename, err)
	}
	return w.Bytes(), nil
}

// unmarshalValues reads the values defined in
// the values.yml file is the file is present
// in the same directory as the filter group yaml file.
func unmarshalValues(filename string) (interface{}, error) {
	path := filepath.Join(filepath.Dir(filename), "values.yml")
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil
	}
	var rawValues interface{}
	err = yaml.Unmarshal(f, &rawValues)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal yaml: %v", err)
	}
	return rawValues, nil
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

// TmplData is the template data object. Some
// fields of this structure represent empty
// values, since we have to satisfy the presence
// of certain keys when executing the template.
type TmplData struct {
	Filter *FilterConfig
	Group  *FilterGroup
	Kevt   *kevent.Kevent
}

func tmplData() TmplData {
	return TmplData{
		Filter: &FilterConfig{},
		Group:  &FilterGroup{},
		Kevt:   kevent.Empty(),
	}
}

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
			if gn.Value == "from-strings" {
				content := n.Content[i+1]
				// for each node in from-strings
				for _, s := range content.Content {
					for j, e := range s.Content {
						if e.Value == "action" && s.Content[j+1].Value != "" {
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
