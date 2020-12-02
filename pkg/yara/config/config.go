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
	"github.com/mitchellh/mapstructure"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"path/filepath"
	"strings"
	"time"
)

const (
	enabled            = "yara.enabled"
	alertVia           = "yara.alert-via"
	alertTextTemplate  = "yara.alert-template.text"
	alertTitleTemplate = "yara.alert-template.title"
	fastScanMode       = "yara.fastscan"
	scanTimeout        = "yara.scan-timeout"
	skipFiles          = "yara.skip-files"
	excludedProcesses  = "yara.excluded-procs"
	excludedFiles      = "yara.excluded-files"
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

// Config stores YARA watcher specific configuration.
type Config struct {
	// Enabled indicates if YARA watcher is enabled.
	Enabled bool `json:"yara.enabled" yaml:"yara.enabled"`
	// Rule contains rule-specific settings.
	Rule Rule `json:"yara.rule" yaml:"yara.rule" mapstructure:"rule"`
	// AlertVia defines which alert sender is used to emit the alert on rule matches.
	AlertVia string `json:"yara.alert-via" yaml:"yara.alert-via"`
	// AlertTemplate defines the template that is used to render the text of the alert.
	AlertTextTemplate string `json:"yara.alert-text-template" yaml:"yara.alert-text-template"`
	// AlertTitle represents the template for the alert title
	AlertTitleTemplate string `json:"yara.alert-title-template" yaml:"yara.alert-title-template"`
	// FastScanMode avoids multiple matches of the same string when not necessary.
	FastScanMode bool `json:"yara.fastscan" yaml:"yara.fastscan"`
	// ScanTimeout sets the timeout for the scanner. If the timeout is reached, the scan operation is cancelled.
	ScanTimeout time.Duration `json:"yara.scan-timeout" yaml:"yara.scan-timeout"`
	// SkipFiles indicates whether file scanning is disabled
	SkipFiles bool `json:"yara.skip-files" yaml:"yara.skip-files"`
	// ExcludedProcesses contains the list of the process' image names that shouldn't be scanned
	ExcludedProcesses []string `json:"yara.excluded-procs" yaml:"yara.excluded-procs"`
	// ExcludedProcesses contains the list of the file names that shouldn't be scanned
	ExcludedFiles []string `json:"yara.excluded-files" yaml:"yara.excluded-files"`
}

// InitFromViper initializes Yara config from Viper.
func (c *Config) InitFromViper(v *viper.Viper) {
	c.Enabled = v.GetBool(enabled)
	c.AlertVia = v.GetString(alertVia)
	c.AlertTextTemplate = v.GetString(alertTextTemplate)
	c.AlertTitleTemplate = v.GetString(alertTitleTemplate)
	c.FastScanMode = v.GetBool(fastScanMode)
	c.ScanTimeout = v.GetDuration(scanTimeout)
	c.SkipFiles = v.GetBool(skipFiles)
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
	flags.String(alertVia, "mail", "Defines which alert sender is used to emit the alert on rule matches")
	flags.String(alertTextTemplate, "", "Defines the template that is used to render the text of the alert")
	flags.String(alertTitleTemplate, "", "Defines the template that is used to render the title of the alert")
	flags.Bool(fastScanMode, true, "Avoids multiple matches of the same string when not necessary")
	flags.Duration(scanTimeout, time.Second*10, "Specifies the timeout for the scanner. If the timeout is reached, the scan operation is cancelled")
	flags.Bool(skipFiles, true, "Indicates whether file scanning is disabled")
	flags.StringSlice(excludedFiles, []string{}, "Contains the list of the comma-separated file names that shouldn't be scanned")
	flags.StringSlice(excludedProcesses, []string{}, "Contains the list of the comma-separated process' image names that shouldn't be scanned")
}

// ShouldSkipProcess determines whether the specified process name is rejected by the scanner.
func (c Config) ShouldSkipProcess(ps string) bool {
	for _, proc := range c.ExcludedProcesses {
		if strings.ToLower(proc) == strings.ToLower(ps) {
			return true
		}
	}
	return false
}

// ShouldSkipFile determines whether the specified file name is rejected by the scanner.
func (c Config) ShouldSkipFile(file string) bool {
	for _, f := range c.ExcludedFiles {
		if strings.ToLower(f) == strings.ToLower(filepath.Base(file)) {
			return true
		}
	}
	return false
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
