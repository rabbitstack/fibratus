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
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	"github.com/rabbitstack/fibratus/pkg/util/log"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	yara "github.com/rabbitstack/fibratus/pkg/yara/config"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

const (
	kcapFile   = "kcap.file"
	configFile = "config-file"

	serializeEnvs = "kevent.serialize-envs"
)

// BaseConfig contains common fields for configuration sections.
type BaseConfig struct {
	// Kstream stores different configuration options for fine tuning thea kstream consumer/controller settings.
	Kstream KstreamConfig `json:"kstream" yaml:"kstream"`
	// Filament contains filament settings
	Filament FilamentConfig `json:"filament" yaml:"filament"`

	// API stores global HTTP API preferences
	API APIConfig `json:"api" yaml:"api"`
	// Yara contains configuration that influences the behaviour of the Yara engine
	Yara yara.Config `json:"yara" yaml:"yara"`
	// Aggregator stores event aggregator configuration
	Aggregator aggregator.Config `json:"aggregator" yaml:"aggregator"`
	// Log contains log-specific configuration options
	Log log.Config `json:"logging" yaml:"logging"`

	// Output stores the currently active output config
	Output outputs.Config
	// Transformers stores transformer configurations
	Transformers []transformers.Config
	// Alertsenders stores alert sender configurations
	Alertsenders []alertsender.Config

	// Filters contains filter group definitions
	Filters *Filters `json:"filters" yaml:"filters"`

	// KcapFile specifies the kcap output file name
	KcapFile string

	flags *pflag.FlagSet
	viper *viper.Viper
	opts  *Options
}

// Options determines which config flags are toggled depending on the command type.
type Options struct {
	capture bool
	replay  bool
	run     bool
	list    bool
	stats   bool
}

// Option is the type alias for the config option.
type Option func(*Options)

// WithCapture determines the capture command is executed.
func WithCapture() Option {
	return func(o *Options) {
		o.capture = true
	}
}

// WithReplay determines the replay command is executed.
func WithReplay() Option {
	return func(o *Options) {
		o.replay = true
	}
}

// WithRun determines the main command is executed.
func WithRun() Option {
	return func(o *Options) {
		o.run = true
	}
}

// WithList determines the list command is executed.
func WithList() Option {
	return func(o *Options) {
		o.list = true
	}
}

// WithStats determines the stats command is executed.
func WithStats() Option {
	return func(o *Options) {
		o.stats = true
	}
}

// TryLoadFile attempts to load the configuration file from specified path on the file system.
func (c *BaseConfig) TryLoadFile(file string) error {
	c.viper.SetConfigFile(file)
	return c.viper.ReadInConfig()
}

// Validate ensures that all configuration options provided by user have the expected values. It returns
// a list of validation errors prefixed with the offending configuration property/flag.
func (c *BaseConfig) Validate() error {
	// we'll first validate the structure and values of the config file
	file := c.viper.GetString(configFile)
	var out interface{}
	b, err := ioutil.ReadFile(file)
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
	// validate config file content
	valid, errs := validate(interpolateSchema(), out)
	if !valid || len(errs) > 0 {
		return fmt.Errorf("invalid config: %v", multierror.Wrap(errs...))
	}
	// now validate the Viper config flags
	valid, errs = validate(interpolateSchema(), c.viper.AllSettings())
	if !valid || len(errs) > 0 {
		return fmt.Errorf("invalid config: %v", multierror.Wrap(errs...))
	}
	return nil
}

// GetConfigFile gets the path of the configuration file from Viper value.
func (c Config) GetConfigFile() string { return c.viper.GetString(configFile) }

// MustViperize adds the flag set to the Cobra command and binds them within the Viper flags.
func (c *BaseConfig) MustViperize(cmd *cobra.Command) {
	cmd.PersistentFlags().AddFlagSet(c.flags)
	if err := c.viper.BindPFlags(cmd.PersistentFlags()); err != nil {
		panic(err)
	}
	if c.opts.capture || c.opts.replay {
		if err := cmd.MarkPersistentFlagRequired(kcapFile); err != nil {
			panic(err)
		}
	}
}

func newWithOpts(options ...Option) *Config {
	opts := &Options{}

	for _, opt := range options {
		opt(opts)
	}

	v := viper.New()
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	flagSet := new(pflag.FlagSet)

	c := &Config{
		BaseConfig: BaseConfig{
			Kstream:    KstreamConfig{},
			Filament:   FilamentConfig{},
			API:        APIConfig{},
			Log:        log.Config{},
			Aggregator: aggregator.Config{},
			Filters:    &Filters{},
			viper:      v,
			flags:      flagSet,
			opts:       opts,
		},
	}

	if opts.run || opts.replay {
		aggregator.AddFlags(flagSet)
		console.AddFlags(flagSet)
		amqp.AddFlags(flagSet)
		elasticsearch.AddFlags(flagSet)
		removet.AddFlags(flagSet)
		replacet.AddFlags(flagSet)
		renamet.AddFlags(flagSet)
		trimt.AddFlags(flagSet)
		tagst.AddFlags(flagSet)
		mailsender.AddFlags(flagSet)
		slacksender.AddFlags(flagSet)
		yara.AddFlags(flagSet)
	}

	return c
}

func (c *BaseConfig) init() error {
	c.Kstream.initFromViper(c.viper)
	c.Filament.initFromViper(c.viper)
	c.API.initFromViper(c.viper)
	c.Aggregator.InitFromViper(c.viper)
	c.Log.InitFromViper(c.viper)
	c.Yara.InitFromViper(c.viper)
	c.Filters.initFromViper(c.viper)

	c.KcapFile = c.viper.GetString(kcapFile)

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

func (c *BaseConfig) addCommonFlags() {
	if c.opts.run || c.opts.replay {
		c.flags.StringP(filamentName, "f", "", "Specifies the filament to execute")
		c.flags.StringSlice(rulesFromPaths, []string{}, "Comma-separated list of rules files")
		c.flags.StringSlice(rulesFromURLs, []string{}, "Comma-separated list of rules URL resources")
	}
	if c.opts.capture {
		c.flags.StringP(kcapFile, "o", "", "The path of the output kcap file")
	}
	if c.opts.replay {
		c.flags.StringP(kcapFile, "k", "", "The path of the input kcap file")
	}
	if c.opts.run || c.opts.replay || c.opts.capture || c.opts.stats {
		c.flags.String(transport, `localhost:8080`, "Specifies the underlying transport protocol for the API HTTP server")
		c.flags.Duration(timeout, time.Second*15, "Determines the timeout for the API server responses")
	}
	c.Log.AddFlags(c.flags)
}
