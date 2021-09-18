//go:build windows
// +build windows

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

package pe

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"path/filepath"
	"strings"
)

const (
	enabled        = "pe.enabled"
	readResources  = "pe.read-resources"
	readSymbols    = "pe.read-symbols"
	readSections   = "pe.read-sections"
	excludedImages = "pe.excluded-images"
)

// Config stores the preferences that dictate the behaviour of the PE reader.
type Config struct {
	Enabled        bool     `json:"pe.enabled" yaml:"pe.enabled"`
	ReadResources  bool     `json:"pe.read-resources" yaml:"pe.read-resources"`
	ReadSymbols    bool     `json:"pe.read-symbols" yaml:"pe.read-symbols"`
	ReadSections   bool     `json:"pe.read-sections" yaml:"pe.read-sections"`
	ExcludedImages []string `json:"pe.excluded-images" yaml:"pe.excluded-images"`
}

// InitFromViper initializes PE config from Viper.
func (c *Config) InitFromViper(v *viper.Viper) {
	c.Enabled = v.GetBool(enabled)
	c.ReadResources = v.GetBool(readResources)
	c.ReadSymbols = v.GetBool(readSymbols)
	c.ReadSections = v.GetBool(readSections)
	c.ExcludedImages = v.GetStringSlice(excludedImages)
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(enabled, false, "Specifies if PE metadata is fetched from the process' image file")
	flags.Bool(readResources, false, "Determines if resources are read from the PE resource directory")
	flags.Bool(readSymbols, false, "Indicates if symbols are read from the PE")
	flags.Bool(readSections, false, "Indicates if full section inspection is allowed")
	flags.StringSlice(excludedImages, []string{}, "Contains a list of comma-separated images names that are excluded from PE parsing")
}

// ShouldSkipProcess determines whether the specified filename name is ignored by PE reader.
func (c Config) shouldSkipImage(filename string) bool {
	for _, img := range c.ExcludedImages {
		if strings.EqualFold(img, filepath.Base(filename)) {
			return true
		}
	}
	return false
}
