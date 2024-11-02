/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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
	"github.com/mitchellh/mapstructure"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
	ytypes "github.com/rabbitstack/fibratus/pkg/yara/types"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"strings"
	"text/template"
	"time"
)

const (
	enabled           = "yara.enabled"
	alertTemplate     = "yara.alert-template"
	fastScanMode      = "yara.fastscan"
	scanTimeout       = "yara.scan-timeout"
	skipFiles         = "yara.skip-files"
	skipAllocs        = "yara.skip-allocs"
	skipMmaps         = "yara.skip-mmaps"
	skipRegistry      = "yara.skip-registry"
	excludedProcesses = "yara.excluded-procs"
	excludedFiles     = "yara.excluded-files"
)

const (
	FileThreatAlertTitle   = "File Threat Detected"
	MemoryThreatAlertTitle = "Memory Threat Detected"
)

// RulePath contains the rule path information.
type RulePath struct {
	Path      string `json:"path" yaml:"path" mapstructure:"path"`
	Namespace string `json:"namespace" yaml:"namespace" mapstructure:"namespace"`
}

// RuleString contains the in-place strings for the rule definition.
type RuleString struct {
	String    string `json:"string" yaml:"string" mapstructure:"string"`
	Namespace string `json:"namespace" yaml:"namespace" mapstructure:"namespace"`
}

// Rule contains rule-specific settings.
type Rule struct {
	// Paths defines the location of the yara rules
	Paths []RulePath `json:"yara.rule.paths" yaml:"yara.rule.paths" mapstructure:"paths"`
	// Strings contains the raw rule definitions
	Strings []RuleString `json:"yara.rule.strings" yaml:"yara.rule.strings" mapstructure:"strings"`
}

// Config stores YARA scanner specific configuration.
type Config struct {
	// Enabled indicates if YARA watcher is enabled.
	Enabled bool `json:"yara.enabled" yaml:"yara.enabled"`
	// Rule contains rule-specific settings.
	Rule Rule `json:"yara.rule" yaml:"yara.rule" mapstructure:"rule"`
	// AlertTemplate represents the template for the alert title
	AlertTemplate string `json:"yara.alert-template" yaml:"yara.alert-template"`
	// FastScanMode avoids multiple matches of the same string when not necessary.
	FastScanMode bool `json:"yara.fastscan" yaml:"yara.fastscan"`
	// ScanTimeout sets the timeout for the scanner. If the timeout is reached, the scan operation is cancelled.
	ScanTimeout time.Duration `json:"yara.scan-timeout" yaml:"yara.scan-timeout"`
	// SkipFiles indicates whether file scanning is disabled.
	SkipFiles bool `json:"yara.skip-files" yaml:"yara.skip-files"`
	// SkipAllocs indicates whether scanning on suspicious memory allocations is disabled.
	SkipAllocs bool `json:"yara.skip-allocs" yaml:"yara.skip-allocs"`
	// SkipMmaps indicates whether scanning on suspicious mappings of sections is disabled.
	SkipMmaps bool `json:"yara.skip-mmaps" yaml:"yara.skip-mmaps"`
	// SkipRegistry indicates whether registry value scanning is disabled.
	SkipRegistry bool `json:"yara.skip-registry" yaml:"yara.skip-registry"`
	// ExcludedProcesses contains the list of the comma-separated process image paths that shouldn't be scanned.
	// Wildcard matching is possible.
	ExcludedProcesses []string `json:"yara.excluded-procs" yaml:"yara.excluded-procs"`
	// ExcludedProcesses contains the list of the comma-separated file paths that shouldn't be scanned.
	// Wildcard matching is possible.
	ExcludedFiles []string `json:"yara.excluded-files" yaml:"yara.excluded-files"`
}

// InitFromViper initializes Yara config from Viper.
func (c *Config) InitFromViper(v *viper.Viper) {
	c.Enabled = v.GetBool(enabled)
	c.AlertTemplate = v.GetString(alertTemplate)
	c.FastScanMode = v.GetBool(fastScanMode)
	c.ScanTimeout = v.GetDuration(scanTimeout)
	c.SkipFiles = v.GetBool(skipFiles)
	c.SkipAllocs = v.GetBool(skipAllocs)
	c.SkipMmaps = v.GetBool(skipMmaps)
	c.SkipRegistry = v.GetBool(skipRegistry)
	c.ExcludedFiles = v.GetStringSlice(excludedFiles)
	c.ExcludedProcesses = v.GetStringSlice(excludedProcesses)

	all := v.AllSettings()
	if _, ok := all["yara"]; !ok {
		return
	}
	if _, ok := all["yara"].(map[string]interface{}); !ok {
		return
	}

	var r Rule
	_ = decode(all["yara"].(map[string]interface{})["rule"], &r)
	c.Rule = r
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enabled, false, "Specifies if Yara scanner is enabled")
	flags.String(alertTemplate, "", "Defines the template that is used to render the alert. By default only the threat/rule name is rendered")
	flags.Bool(fastScanMode, true, "Avoids multiple matches of the same string when not necessary")
	flags.Duration(scanTimeout, time.Second*10, "Specifies the timeout for the scanner. If the timeout is reached, the scan operation is cancelled")
	flags.Bool(skipFiles, false, "Indicates whether file scanning is disabled")
	flags.Bool(skipAllocs, false, "Indicates whether scanning on suspicious memory allocations is disabled")
	flags.Bool(skipMmaps, false, "Indicates whether scanning on suspicious mappings of sections is disabled")
	flags.Bool(skipRegistry, false, "Indicates whether registry value scanning is disabled")
	flags.StringSlice(excludedFiles, []string{}, "Contains the list of the comma-separated file paths that shouldn't be scanned. Wildcard matching is possible")
	flags.StringSlice(excludedProcesses, []string{}, "Contains the list of the comma-separated process image paths that shouldn't be scanned. Wildcard matching is possible")
}

// ShouldSkipProcess determines whether the specified full process image path is rejected by the scanner.
// Wildcard matching is possible.
func (c Config) ShouldSkipProcess(proc string) bool {
	for _, p := range c.ExcludedProcesses {
		if wildcard.Match(strings.ToLower(p), strings.ToLower(proc)) {
			return true
		}
	}
	return false
}

// ShouldSkipFile determines whether the specified full file path is rejected by the scanner.
func (c Config) ShouldSkipFile(file string) bool {
	for _, f := range c.ExcludedFiles {
		if wildcard.Match(strings.ToLower(f), strings.ToLower(file)) {
			return true
		}
	}
	return false
}

// AlertTitle returns the brief alert title depending on
// whether the process scan took place or a file/registry
// key was scanned.
func (c Config) AlertTitle(e *kevent.Kevent) string {
	if (e.Category == ktypes.File && e.Kparams.Contains(kparams.FileName)) || e.Category == ktypes.Registry {
		return FileThreatAlertTitle
	}
	return MemoryThreatAlertTitle
}

// AlertText returns the short alert text if the Go template is
// not specified. On the contrary, the provided Go template is
// parsed and executing yielding the alert text.
func (c Config) AlertText(e *kevent.Kevent, match ytypes.MatchRule) (string, error) {
	if c.AlertTemplate == "" {
		threat := match.ThreatName()
		if threat == "" {
			threat = match.Rule
		}
		return fmt.Sprintf("Threat detected %s", threat), nil
	}

	var writer bytes.Buffer
	var data = struct {
		Match ytypes.MatchRule
		Event *kevent.Kevent
	}{
		match,
		e,
	}

	tmpl, err := template.New("yara").Parse(c.AlertTemplate)
	if err != nil {
		return "", fmt.Errorf("yara alert template syntax error: %v", err)
	}
	err = tmpl.Execute(&writer, data)
	if err != nil {
		return "", fmt.Errorf("couldn't execute yara alert template: %v", err)
	}

	return writer.String(), nil
}

func decode(input, output interface{}) error {
	var decoderConfig = &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           output,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
		),
	}
	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return err
	}
	return decoder.Decode(input)
}
