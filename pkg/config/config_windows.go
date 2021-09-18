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
	"time"

	"os"
	"path/filepath"

	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"github.com/rabbitstack/fibratus/pkg/outputs/null"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"

	"github.com/rabbitstack/fibratus/pkg/pe"
)

const (
	debugPrivilege     = "debug-privilege"
	initHandleSnapshot = "handle.init-snapshot"

	serializeThreads = "kevent.serialize-threads"
	serializeImages  = "kevent.serialize-images"
	serializeHandles = "kevent.serialize-handles"
	serializePE      = "kevent.serialize-pe"
)

// Config stores configuration options for fine tuning the behaviour of Fibratus.
type Config struct {
	BaseConfig
	// PE contains the settings that influences the behaviour of the PE (Portable Executable) reader.
	PE pe.Config `json:"pe" yaml:"pe"`
	// InitHandleSnapshot indicates whether initial handle snapshot is built
	InitHandleSnapshot bool `json:"init-handle-snapshot" yaml:"init-handle-snapshot"`
	// DebugPrivilege determines whether fibratus process token acquires the debug privilege
	DebugPrivilege bool `json:"debug-privilege" yaml:"debug-privilege"`
}

// NewWithOpts builds a new configuration store from a variety of sources such as configuration files,
// environment variables or command line flags.
func NewWithOpts(options ...Option) *Config {
	config := newWithOpts(options...)

	opts := &Options{}

	for _, opt := range options {
		opt(opts)
	}

	if opts.run || opts.capture {
		pe.AddFlags(config.flags)
	}

	config.addFlags()

	return config
}

// Init setups the configuration state from Viper.
func (c *Config) Init() error {
	c.PE.InitFromViper(c.viper)

	c.InitHandleSnapshot = c.viper.GetBool(initHandleSnapshot)
	c.DebugPrivilege = c.viper.GetBool(debugPrivilege)

	kevent.SerializeThreads = c.viper.GetBool(serializeThreads)
	kevent.SerializeImages = c.viper.GetBool(serializeImages)
	kevent.SerializeHandles = c.viper.GetBool(serializeHandles)
	kevent.SerializePE = c.viper.GetBool(serializePE)
	kevent.SerializeEnvs = c.viper.GetBool(serializeEnvs)

	if err := c.init(); err != nil {
		return err
	}

	// if it is not an interactive session but the console output is enabled
	// we default to null output and warn about that
	if isWindowsService() && c.Output.Output != nil {
		if c.Output.Type == outputs.Console {
			log.Warn("running in non-interactive session with console output. " +
				"Please configure a different output type. Defaulting to null output")
			c.Output.Type, c.Output.Output = outputs.Null, &null.Config{}
			return nil
		}
	}
	return nil
}

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
		c.flags.Bool(initHandleSnapshot, true, "Indicates whether initial handle snapshot is built. This implies scanning the system handles table and producing an entry for each handle object")

		c.flags.Bool(enableThreadKevents, true, "Determines whether thread kernel events are collected by Kernel Logger provider")
		c.flags.Bool(enableRegistryKevents, true, "Determines whether registry kernel events are collected by Kernel Logger provider")
		c.flags.Bool(enableNetKevents, true, "Determines whether network (TCP/UDP) kernel events are collected by Kernel Logger provider")
		c.flags.Bool(enableFileIOKevents, true, "Determines whether disk I/O kernel events are collected by Kernel Logger provider")
		c.flags.Bool(enableImageKevents, true, "Determines whether file I/O kernel events are collected by Kernel Logger provider")
		c.flags.Bool(enableHandleKevents, false, "Determines whether object manager kernel events (handle creation/destruction) are collected by Kernel Logger provider")
		c.flags.Int(bufferSize, int(maxBufferSize), "Represents the amount of memory allocated for each event tracing session buffer, in kilobytes. The buffer size affects the rate at which buffers fill and must be flushed (small buffer size requires less memory but it increases the rate at which buffers must be flushed)")
		c.flags.Int(minBuffers, int(defaultMinBuffers), "Determines the minimum number of buffers allocated for the event tracing session's buffer pool")
		c.flags.Int(maxBuffers, int(defaultMaxBuffers), "Determines the maximum number of buffers allocated for the event tracing session's buffer pool")
		c.flags.Duration(flushInterval, defaultFlushInterval, "Specifies how often the trace buffers are forcibly flushed")
		c.flags.StringSlice(blacklistEvents, []string{}, "A list of symbolical kernel event names that will be dropped from the kernel event stream. By default all events are accepted")
		c.flags.StringSlice(blacklistImages, []string{"System"}, "A list of image names that will be dropped from the kernel event stream. Image names are case insensitive")

		c.flags.Bool(serializeThreads, false, "Indicates if threads are serialized as part of the process state")
		c.flags.Bool(serializeImages, false, "Indicates if images are serialized as part of the process state")
		c.flags.Bool(serializeHandles, false, "Indicates if handles are serialized as part of the process state")
		c.flags.Bool(serializePE, false, "Indicates if the PE metadata are serialized as part of the process state")
		c.flags.Bool(serializeEnvs, true, "Indicates if environment variables are serialized as part of the process state")
	}
	c.Log.AddFlags(c.flags)
}

// isWindowsService returns true if fibratus is running as Windows service.
func isWindowsService() bool {
	in, err := svc.IsAnInteractiveSession()
	if err != nil {
		return false
	}
	return !in
}
