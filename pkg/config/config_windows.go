//go:build windows

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
	"github.com/rabbitstack/fibratus/internal/evasion"
	"golang.org/x/sys/windows"

	"github.com/rabbitstack/fibratus/pkg/event"

	"os"
	"path/filepath"

	"github.com/rabbitstack/fibratus/pkg/alertsender/eventlog"
	"github.com/rabbitstack/fibratus/pkg/alertsender/systray"
	"github.com/rabbitstack/fibratus/pkg/pe"
	yara "github.com/rabbitstack/fibratus/pkg/yara/config"
)

const (
	debugPrivilege           = "debug-privilege"
	initHandleSnapshot       = "handle.init-snapshot"
	enumerateHandles         = "handle.enumerate-handles"
	symbolPaths              = "symbol-paths"
	symbolizeKernelAddresses = "symbolize-kernel-addresses"

	serializeThreads = "event.serialize-threads"
	serializeModules = "event.serialize-modules"
	serializeEnvs    = "event.serialize-envs"
	serializeHandles = "event.serialize-handles"
	serializePE      = "event.serialize-pe"
)

var (
	// configFilePath defines the default value for the configuration file path
	configFilePath = filepath.Join(os.Getenv("PROGRAMFILES"), "fibratus", "config", "fibratus.yml")

	// filamentsPaths defines the default directory containing filament scripts
	filamentsPaths = filepath.Join(os.Getenv("PROGRAMFILES"), "fibratus", "filaments")

	// rulesPaths defines default rule paths
	rulesPaths = []string{filepath.Join(rulesDir(), "*")}

	// macrosPaths defines default macro paths
	macrosPaths = []string{filepath.Join(rulesDir(), "Macros", "*")}

	// apiTransport defines the default transport protocol for the API server
	apiTransport = "http://localhost:8482"
)

// Config exposes the platform configuration options.
type Config struct {
	*BaseConfig
	// PE contains the settings that influences the behaviour of the PE (Portable Executable) reader.
	PE pe.Config `json:"pe" yaml:"pe"`

	// InitHandleSnapshot indicates whether initial handle snapshot is built
	InitHandleSnapshot bool `json:"init-handle-snapshot" yaml:"init-handle-snapshot"`

	// EnumerateHandles indicates if process handles are collected during startup or
	// when a new process is spawn
	EnumerateHandles bool `json:"enumerate-handles" yaml:"enumerate-handles"`

	// SymbolPaths designates the path or a series of paths separated by a semicolon
	// that is used to search for symbols files.
	SymbolPaths string `json:"symbol-paths" yaml:"symbols-paths"`

	// SymbolizeKernelAddresses determines if kernel stack addresses are symbolized.
	SymbolizeKernelAddresses bool `json:"symbolize-kernel-addresses" yaml:"symbolize-kernel-addresses"`

	// DebugPrivilege dictates if the SeDebugPrivilege is injected into
	// Fibratus process' access token.
	DebugPrivilege bool `json:"debug-privilege" yaml:"debug-privilege"`

	// Yara contains configuration that influences the behaviour of the Yara engine
	Yara yara.Config `json:"yara" yaml:"yara"`

	// Evasion controls the detection of evasion behaviours.
	Evasion evasion.Config `json:"evasion" yaml:"evasion"`
}

// NewWithOpts builds a new platform configuration store.
func NewWithOpts(options ...Option) *Config {
	c := &Config{
		BaseConfig: newWithOpts(options...),
		PE:         pe.Config{},
		Yara:       yara.Config{},
	}

	c.addFlags()

	return c
}

// Init initializes the config state.
func (c *Config) Init() error {
	c.initFromViper()
	return c.BaseConfig.init()
}

// addFlags populates the platform flags set.
func (c *Config) addFlags() {
	if c.opts.run || c.opts.replay {
		systray.AddFlags(c.flags)
		eventlog.AddFlags(c.flags)
		yara.AddFlags(c.flags)
	}
	if c.opts.run || c.opts.capture {
		pe.AddFlags(c.flags)
	}
	if c.opts.run {
		evasion.AddFlags(c.flags)
	}
	if c.opts.run || c.opts.capture {
		c.flags.Bool(initHandleSnapshot, false, "Indicates whether the initial handle snapshot is built")
		c.flags.Bool(debugPrivilege, true, "Dictates if the SeDebugPrivilege is injected into the process token")
		c.flags.Bool(enumerateHandles, false, "Indicates if process handles are collected")
		c.flags.String(symbolPaths, "srv*c:\\\\SymCache*https://msdl.microsoft.com/download/symbols", "Designates paths used to search for symbol files")
		c.flags.Bool(symbolizeKernelAddresses, false, "Determines if kernel stack addresses are symbolized")
		c.flags.Bool(serializeThreads, false, "Indicates if threads are serialized as part of process state")
		c.flags.Bool(serializeModules, false, "Indicates if modules are serialized as part of process state")
		c.flags.Bool(serializeHandles, false, "Indicates if handles are serialized as part of process state")
		c.flags.Bool(serializePE, false, "Indicates if PE metadata is serialized as part of process state")
		c.flags.Bool(serializeEnvs, true, "Indicates if environment variables are serialized as part of process state")
	}
}

func (c *Config) initFromViper() {
	c.PE.InitFromViper(c.viper)
	c.Yara.InitFromViper(c.viper)
	c.InitHandleSnapshot = c.viper.GetBool(initHandleSnapshot)
	c.EnumerateHandles = c.viper.GetBool(enumerateHandles)
	c.SymbolPaths = c.viper.GetString(symbolPaths)
	c.SymbolizeKernelAddresses = c.viper.GetBool(symbolizeKernelAddresses)
	c.DebugPrivilege = c.viper.GetBool(debugPrivilege)
	event.SerializeThreads = c.viper.GetBool(serializeThreads)
	event.SerializeModules = c.viper.GetBool(serializeModules)
	event.SerializeHandles = c.viper.GetBool(serializeHandles)
	event.SerializePE = c.viper.GetBool(serializePE)
	event.SerializeEnvs = c.viper.GetBool(serializeEnvs)
	if c.opts.run {
		c.Evasion.InitFromViper(c.viper)
	}
}

func rulesDir() string {
	exe, err := os.Executable()
	if err != nil {
		exe = filepath.Join(os.Getenv("ProgramFiles"), "Fibratus", "Bin", "fibratus.exe")
	}
	return filepath.Join(filepath.Dir(exe), "..", "Rules")
}

// SymbolPathsUTF16 returns the symbol paths as a UTF-16 string.
func (c *Config) SymbolPathsUTF16() *uint16 {
	paths, _ := windows.UTF16PtrFromString(c.SymbolPaths)
	return paths
}
