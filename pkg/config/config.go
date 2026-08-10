/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rabbitstack/fibratus/pkg/aggregator"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	removet "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/remove"
	renamet "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/rename"
	replacet "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/replace"
	tagst "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/tags"
	trimt "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/trim"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	mailsender "github.com/rabbitstack/fibratus/pkg/alertsender/mail"
	slacksender "github.com/rabbitstack/fibratus/pkg/alertsender/slack"
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/console"
	"github.com/rabbitstack/fibratus/pkg/outputs/elasticsearch"
	"github.com/rabbitstack/fibratus/pkg/outputs/http"
	"github.com/rabbitstack/fibratus/pkg/util/log"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

const (
	capFile     = "cap.file"
	configFile  = "config-file"
	forwardMode = "forward"
)

// Config stores configuration options for fine-tuning the behaviour of Fibratus.
type Config struct {
	platformConfig

	EventSource  EventSourceConfig `json:"eventsource" yaml:"eventsource"`
	Filament     FilamentConfig    `json:"filament" yaml:"filament"`
	API          APIConfig         `json:"api" yaml:"api"`
	Output       outputs.Config
	Aggregator   aggregator.Config `json:"aggregator" yaml:"aggregator"`
	Log          log.Config        `json:"logging" yaml:"logging"`
	Transformers []transformers.Config
	Alertsenders []alertsender.Config
	Filters      *Filters `json:"filters" yaml:"filters"`
	ForwardMode  bool     `json:"forward" yaml:"forward"`
	CapFile      string

	flags *pflag.FlagSet
	viper *viper.Viper
	opts  *Options
}

// Options determines which config flags are toggled depending on the command type.
type Options struct {
	capture  bool
	replay   bool
	run      bool
	list     bool
	stats    bool
	validate bool
}

// Option configures the command-specific configuration surface.
type Option func(*Options)

func WithCapture() Option  { return func(o *Options) { o.capture = true } }
func WithReplay() Option   { return func(o *Options) { o.replay = true } }
func WithRun() Option      { return func(o *Options) { o.run = true } }
func WithList() Option     { return func(o *Options) { o.list = true } }
func WithStats() Option    { return func(o *Options) { o.stats = true } }
func WithValidate() Option { return func(o *Options) { o.validate = true } }

// NewWithOpts builds a new configuration store from files, environment variables, and flags.
func NewWithOpts(options ...Option) *Config {
	opts := &Options{}
	for _, option := range options {
		option(opts)
	}

	v := viper.New()
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	c := &Config{
		platformConfig: newPlatformConfig(),
		EventSource:    EventSourceConfig{},
		Filament:       FilamentConfig{},
		API:            APIConfig{},
		Aggregator:     aggregator.Config{},
		Log:            log.Config{},
		Filters:        &Filters{},
		flags:          new(pflag.FlagSet),
		viper:          v,
		opts:           opts,
	}

	if opts.run || opts.replay {
		aggregator.AddFlags(c.flags)
		console.AddFlags(c.flags)
		amqp.AddFlags(c.flags)
		elasticsearch.AddFlags(c.flags)
		http.AddFlags(c.flags)
		removet.AddFlags(c.flags)
		replacet.AddFlags(c.flags)
		renamet.AddFlags(c.flags)
		trimt.AddFlags(c.flags)
		tagst.AddFlags(c.flags)
		mailsender.AddFlags(c.flags)
		slacksender.AddFlags(c.flags)
	}

	c.addFlags()
	c.addPlatformFlags()
	return c
}

// MustViperize adds the configuration flags to the Cobra command.
func (c *Config) MustViperize(cmd *cobra.Command) {
	cmd.PersistentFlags().AddFlagSet(c.flags)
	if err := c.viper.BindPFlags(cmd.PersistentFlags()); err != nil {
		panic(err)
	}
	if c.opts.capture || c.opts.replay {
		if err := cmd.MarkPersistentFlagRequired(capFile); err != nil {
			panic(err)
		}
	}
}

// Init initializes the configuration state from Viper.
func (c *Config) Init() error {
	c.EventSource.initFromViper(c.viper)
	c.Filament.initFromViper(c.viper)
	c.API.initFromViper(c.viper)
	c.Aggregator.InitFromViper(c.viper)
	c.Log.InitFromViper(c.viper)
	c.Filters.initFromViper(c.viper)
	c.ForwardMode = c.viper.GetBool(forwardMode)
	c.CapFile = c.viper.GetString(capFile)
	c.initPlatform()

	if c.opts.run || c.opts.replay {
		if err := c.tryLoadOutput(); err != nil {
			return err
		}
		if err := c.tryLoadTransformers(); err != nil {
			return err
		}
		if err := c.tryLoadAlertSenders(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) GetConfigFile() string { return c.viper.GetString(configFile) }

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

func (c *Config) validateConfig() error {
	file := c.viper.GetString(configFile)
	var out interface{}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	switch filepath.Ext(file) {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(b, &out)
	case ".json":
		err = json.Unmarshal(b, &out)
	default:
		return fmt.Errorf("%s is not a supported config file extension", filepath.Ext(file))
	}
	if err != nil {
		return fmt.Errorf("couldn't read the config file: %v", err)
	}
	valid, errs := validate(configSchema, out)
	if !valid || len(errs) > 0 {
		return fmt.Errorf("invalid config: %v", multierror.Wrap(errs...))
	}
	valid, errs = validate(configSchema, c.viper.AllSettings())
	if !valid || len(errs) > 0 {
		return fmt.Errorf("invalid config: %v", multierror.Wrap(errs...))
	}
	return nil
}

func (c *Config) IsCaptureSet() bool  { return c.CapFile != "" }
func (c *Config) IsFilamentSet() bool { return c.Filament.Name != "" }
func (c *Config) ConfigExists() bool  { _, err := os.Stat(c.File()); return err == nil }
func (c *Config) File() string        { return c.viper.GetString(configFile) }

func (c *Config) addFlags() {
	c.flags.String(configFile, defaultConfigFile(), "Indicates the location of the configuration file")
	if c.opts.run {
		c.flags.Bool(forwardMode, false, "Designates if event forwarding mode is engaged")
	}
	if c.opts.run || c.opts.replay || c.opts.validate {
		c.flags.StringP(filamentName, "f", "", "Specifies the filament to execute")
		c.flags.Bool(rulesEnabled, true, "Indicates if the rule engine is enabled and rules loaded")
		c.flags.StringSlice(rulesFromPaths, defaultRulesPaths(), "Comma-separated list of rules files")
		c.flags.StringSlice(macrosFromPaths, defaultMacrosPaths(), "Comma-separated list of macro files")
		c.flags.StringSlice(rulesFromURLs, nil, "Comma-separated list of rules URL resources")
		c.flags.Bool(matchAll, true, "Indicates if the match all strategy is enabled for the rule engine")
	}
	if c.opts.capture {
		c.flags.StringP(capFile, "o", "", "The path of the output cap file")
	}
	if c.opts.replay {
		c.flags.StringP(capFile, "k", "", "The path of the input cap file")
	}
	if c.opts.run || c.opts.replay || c.opts.list || c.opts.validate {
		c.flags.String(filamentPath, defaultFilamentPath(), "Denotes the directory where filaments are located")
	}
	if c.opts.run || c.opts.replay || c.opts.capture || c.opts.stats {
		c.flags.String(transport, "localhost:8080", "Specifies the underlying transport protocol for the API HTTP server")
		c.flags.Duration(timeout, 15*time.Second, "Determines the timeout for the API server responses")
	}
	c.Log.AddFlags(c.flags)
}
