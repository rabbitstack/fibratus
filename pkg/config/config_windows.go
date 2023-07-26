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
	"time"

	"github.com/rabbitstack/fibratus/pkg/outputs/eventlog"

	"github.com/rabbitstack/fibratus/pkg/outputs/http"

	"github.com/rabbitstack/fibratus/pkg/aggregator"
	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	removet "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/remove"
	replacet "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/replace"
	tagst "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/tags"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs/amqp"
	"github.com/rabbitstack/fibratus/pkg/outputs/elasticsearch"
	"github.com/rabbitstack/fibratus/pkg/util/log"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	yara "github.com/rabbitstack/fibratus/pkg/yara/config"
	"gopkg.in/yaml.v3"

	renamet "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/rename"
	trimt "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/trim"

	"os"
	"path/filepath"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/alertsender"
	mailsender "github.com/rabbitstack/fibratus/pkg/alertsender/mail"
	slacksender "github.com/rabbitstack/fibratus/pkg/alertsender/slack"
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"github.com/rabbitstack/fibratus/pkg/outputs/console"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	kcapFile           = "kcap.file"
	configFile         = "config-file"
	debugPrivilege     = "debug-privilege"
	initHandleSnapshot = "handle.init-snapshot"

	serializeThreads = "kevent.serialize-threads"
	serializeImages  = "kevent.serialize-images"
	serializeHandles = "kevent.serialize-handles"
	serializePE      = "kevent.serialize-pe"
	serializeEnvs    = "kevent.serialize-envs"
)

// Config stores configuration options for fine tuning the behaviour of Fibratus.
type Config struct {
	// Kstream stores different configuration options for fine tuning kstream consumer/controller settings.
	Kstream KstreamConfig `json:"kstream" yaml:"kstream"`
	// Filament contains filament settings
	Filament FilamentConfig `json:"filament" yaml:"filament"`
	// PE contains the settings that influences the behaviour of the PE (Portable Executable) reader.
	PE pe.Config `json:"pe" yaml:"pe"`
	// Output stores the currently active output config
	Output outputs.Config
	// InitHandleSnapshot indicates whether initial handle snapshot is built
	InitHandleSnapshot bool `json:"init-handle-snapshot" yaml:"init-handle-snapshot"`
	DebugPrivilege     bool `json:"debug-privilege" yaml:"debug-privilege"`
	KcapFile           string

	// API stores global HTTP API preferences
	API APIConfig `json:"api" yaml:"api"`
	// Yara contains configuration that influences the behaviour of the Yara engine
	Yara yara.Config `json:"yara" yaml:"yara"`
	// Aggregator stores event aggregator configuration
	Aggregator aggregator.Config `json:"aggregator" yaml:"aggregator"`
	// Log contains log-specific configuration options
	Log log.Config `json:"logging" yaml:"logging"`

	// Transformers stores transformer configurations
	Transformers []transformers.Config
	// Alertsenders stores alert sender configurations
	Alertsenders []alertsender.Config

	// Filters contains filter group definitions
	Filters *Filters `json:"filters" yaml:"filters"`

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

// NewWithOpts builds a new configuration store from a variety of sources such as configuration files,
// environment variables or command line flags.
func NewWithOpts(options ...Option) *Config {
	opts := &Options{}

	for _, opt := range options {
		opt(opts)
	}

	v := viper.New()
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	flagSet := new(pflag.FlagSet)

	c := &Config{
		Kstream:    KstreamConfig{},
		Filament:   FilamentConfig{},
		API:        APIConfig{},
		PE:         pe.Config{},
		Log:        log.Config{},
		Aggregator: aggregator.Config{},
		Filters:    &Filters{},
		viper:      v,
		flags:      flagSet,
		opts:       opts,
	}

	if opts.run || opts.replay {
		aggregator.AddFlags(flagSet)
		console.AddFlags(flagSet)
		amqp.AddFlags(flagSet)
		elasticsearch.AddFlags(flagSet)
		http.AddFlags(flagSet)
		eventlog.AddFlags(flagSet)
		removet.AddFlags(flagSet)
		replacet.AddFlags(flagSet)
		renamet.AddFlags(flagSet)
		trimt.AddFlags(flagSet)
		tagst.AddFlags(flagSet)
		mailsender.AddFlags(flagSet)
		slacksender.AddFlags(flagSet)
		yara.AddFlags(flagSet)
	}

	if opts.run || opts.capture {
		pe.AddFlags(flagSet)
	}

	c.addFlags()

	return c
}

// GetConfigFile gets the path of the configuration file from Viper value.
func (c Config) GetConfigFile() string {
	return c.viper.GetString(configFile)
}

// GetRuleGroups returns all rule groups loaded into the engine.
func (c Config) GetRuleGroups() []FilterGroup {
	if c.Filters == nil {
		return nil
	}
	return c.Filters.groups
}

// MustViperize adds the flag set to the Cobra command and binds them within the Viper flags.
func (c *Config) MustViperize(cmd *cobra.Command) {
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

// Init setups the configuration state from Viper.
func (c *Config) Init() error {
	c.Kstream.initFromViper(c.viper)
	c.Filament.initFromViper(c.viper)
	c.API.initFromViper(c.viper)
	c.PE.InitFromViper(c.viper)
	c.Aggregator.InitFromViper(c.viper)
	c.Log.InitFromViper(c.viper)
	c.Yara.InitFromViper(c.viper)
	c.Filters.initFromViper(c.viper)

	c.InitHandleSnapshot = c.viper.GetBool(initHandleSnapshot)
	c.DebugPrivilege = c.viper.GetBool(debugPrivilege)
	c.KcapFile = c.viper.GetString(kcapFile)

	kevent.SerializeThreads = c.viper.GetBool(serializeThreads)
	kevent.SerializeImages = c.viper.GetBool(serializeImages)
	kevent.SerializeHandles = c.viper.GetBool(serializeHandles)
	kevent.SerializePE = c.viper.GetBool(serializePE)
	kevent.SerializeEnvs = c.viper.GetBool(serializeEnvs)

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

// TryLoadFile attempts to load the configuration file from specified path on the file system.
func (c *Config) TryLoadFile(file string) error {
	c.viper.SetConfigFile(file)
	return c.viper.ReadInConfig()
}

// Validate ensures that all configuration options provided by user have the expected values. It returns
// a list of validation errors prefixed with the offending configuration property/flag.
func (c *Config) Validate() error {
	// we'll first validate the structure and values of the config file
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

// File returns the config file path.
func (c *Config) File() string { return c.viper.GetString(configFile) }

func (c *Config) addFlags() {
	c.flags.String(configFile, filepath.Join(os.Getenv("PROGRAMFILES"), "fibratus", "config", "fibratus.yml"), "Indicates the location of the configuration file")
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
	if c.opts.run || c.opts.replay || c.opts.list {
		c.flags.String(filamentPath, filepath.Join(os.Getenv("PROGRAMFILES"), "fibratus", "filaments"), "Denotes the directory where filaments are located")
	}
	if c.opts.run || c.opts.replay || c.opts.capture || c.opts.stats {
		c.flags.String(transport, `localhost:8080`, "Specifies the underlying transport protocol for the API HTTP server")
		c.flags.Duration(timeout, time.Second*15, "Determines the timeout for the API server responses")
	}
	if c.opts.run || c.opts.capture {
		c.flags.Bool(initHandleSnapshot, false, "Indicates whether initial handle snapshot is built. This implies scanning the system handles table and producing an entry for each handle object")

		c.flags.Bool(enableThreadKevents, true, "Determines whether thread kernel events are collected by Kernel Logger provider")
		c.flags.Bool(enableRegistryKevents, true, "Determines whether registry kernel events are collected by Kernel Logger provider")
		c.flags.Bool(enableNetKevents, true, "Determines whether network (TCP/UDP) kernel events are collected by Kernel Logger provider")
		c.flags.Bool(enableFileIOKevents, true, "Determines whether disk I/O kernel events are collected by Kernel Logger provider")
		c.flags.Bool(enableImageKevents, true, "Determines whether file I/O kernel events are collected by Kernel Logger provider")
		c.flags.Bool(enableHandleKevents, false, "Determines whether object manager kernel events (handle creation/destruction) are collected by Kernel Logger provider")
		c.flags.Bool(enableMemKevents, true, "Determines whether memory manager kernel events are collected by Kernel Logger provider")
		c.flags.Bool(enableAuditAPIEvents, true, "Determines whether kernel audit API calls events are published")
		c.flags.Bool(enableDNSEvents, true, "Determines whether DNS client events are enabled")
		c.flags.Int(bufferSize, int(maxBufferSize), "Represents the amount of memory allocated for each event tracing session buffer, in kilobytes. The buffer size affects the rate at which buffers fill and must be flushed (small buffer size requires less memory but it increases the rate at which buffers must be flushed)")
		c.flags.Int(minBuffers, int(defaultMinBuffers), "Determines the minimum number of buffers allocated for the event tracing session's buffer pool")
		c.flags.Int(maxBuffers, int(defaultMaxBuffers), "Determines the maximum number of buffers allocated for the event tracing session's buffer pool")
		c.flags.Duration(flushInterval, defaultFlushInterval, "Specifies how often the trace buffers are forcibly flushed")
		c.flags.StringSlice(excludedEvents, []string{}, "A list of symbolical kernel event names that will be dropped from the event stream. By default all events are accepted")
		c.flags.StringSlice(excludedImages, []string{}, "A list of image names that will be dropped from the event stream. Image names are case sensitive")

		c.flags.Bool(serializeThreads, false, "Indicates if threads are serialized as part of the process state")
		c.flags.Bool(serializeImages, false, "Indicates if images are serialized as part of the process state")
		c.flags.Bool(serializeHandles, false, "Indicates if handles are serialized as part of the process state")
		c.flags.Bool(serializePE, false, "Indicates if the PE metadata are serialized as part of the process state")
		c.flags.Bool(serializeEnvs, true, "Indicates if environment variables are serialized as part of the process state")
	}
	c.Log.AddFlags(c.flags)
}
