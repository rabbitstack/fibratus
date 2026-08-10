//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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
	"os"
	"path/filepath"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/util/log"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const configFile = "config-file"

type Config struct {
	EventSource  EventSourceConfig    `json:"eventsource" yaml:"eventsource"`
	Filament     FilamentConfig       `json:"filament" yaml:"filament"`
	API          APIConfig            `json:"api" yaml:"api"`
	Log          log.Config           `json:"logging" yaml:"logging"`
	Filters      *Filters             `json:"filters" yaml:"filters"`
	ForwardMode  bool                 `json:"forward" yaml:"forward"`
	CapFile      string               `json:"cap.file" yaml:"cap.file"`
	Alertsenders []alertsender.Config `json:"-" yaml:"-"`

	flags *pflag.FlagSet
	viper *viper.Viper
	opts  *Options
}

type Options struct {
	run      bool
	list     bool
	stats    bool
	validate bool
}

type Option func(*Options)

func WithRun() Option      { return func(o *Options) { o.run = true } }
func WithList() Option     { return func(o *Options) { o.list = true } }
func WithStats() Option    { return func(o *Options) { o.stats = true } }
func WithValidate() Option { return func(o *Options) { o.validate = true } }

func NewWithOpts(options ...Option) *Config {
	opts := &Options{}
	for _, option := range options {
		option(opts)
	}
	v := viper.New()
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	c := &Config{
		Filters: &Filters{},
		flags:   new(pflag.FlagSet),
		viper:   v,
		opts:    opts,
	}
	c.flags.String(configFile, filepath.Join("/etc", "fibratus", "fibratus.yml"), "Indicates the location of the configuration file")
	c.flags.String(filamentName, "", "Specifies the filament to execute")
	c.flags.String(filamentPath, "", "Denotes the directory where filaments are located")
	c.flags.String(transport, "localhost:8080", "Specifies the underlying transport protocol for the API HTTP server")
	c.flags.Bool(rulesEnabled, true, "Indicates if the rule engine is enabled and rules loaded")
	c.flags.StringSlice(rulesFromPaths, nil, "Comma-separated list of rules files")
	c.flags.StringSlice(macrosFromPaths, nil, "Comma-separated list of macro files")
	c.flags.StringSlice(rulesFromURLs, nil, "Comma-separated list of rules URL resources")
	c.flags.Bool(matchAll, true, "Indicates if the match all strategy is enabled")
	c.EventSource.AddFlags(c.flags)
	c.Log.AddFlags(c.flags)
	return c
}

func (c *Config) MustViperize(cmd *cobra.Command) {
	cmd.PersistentFlags().AddFlagSet(c.flags)
	if err := c.viper.BindPFlags(cmd.PersistentFlags()); err != nil {
		panic(err)
	}
}

func (c *Config) Init() error {
	c.EventSource.initFromViper(c.viper)
	c.Filament.initFromViper(c.viper)
	c.API.initFromViper(c.viper)
	c.Log.InitFromViper(c.viper)
	c.Filters.initFromViper(c.viper)
	c.ForwardMode = c.viper.GetBool("forward")
	c.CapFile = c.viper.GetString("cap.file")
	if err := c.tryLoadAlertSenders(); err != nil && err != errNoAlertsendersSection {
		return err
	}
	return nil
}

func (c *Config) GetConfigFile() string { return c.viper.GetString(configFile) }
func (c *Config) File() string          { return c.GetConfigFile() }
func (c *Config) GetFilters() []*FilterConfig {
	if c.Filters == nil {
		return nil
	}
	return c.Filters.filters
}
func (c *Config) TryLoadFile(file string) error {
	c.viper.SetConfigFile(file)
	return c.viper.ReadInConfig()
}
func (c *Config) Validate() error     { return nil }
func (c *Config) IsCaptureSet() bool  { return c.CapFile != "" }
func (c *Config) IsFilamentSet() bool { return c.Filament.Name != "" }
func (c *Config) ConfigExists() bool  { _, err := os.Stat(c.File()); return err == nil }
