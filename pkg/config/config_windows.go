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
	"os"
	"path/filepath"

	"github.com/rabbitstack/fibratus/internal/evasion"
	"github.com/rabbitstack/fibratus/pkg/alertsender/eventlog"
	"github.com/rabbitstack/fibratus/pkg/alertsender/systray"
	"github.com/rabbitstack/fibratus/pkg/event"
	outputeventlog "github.com/rabbitstack/fibratus/pkg/outputs/eventlog"
	"github.com/rabbitstack/fibratus/pkg/pe"
	yara "github.com/rabbitstack/fibratus/pkg/yara/config"
	"golang.org/x/sys/windows"
)

const (
	debugPrivilege           = "debug-privilege"
	initHandleSnapshot       = "handle.init-snapshot"
	enumerateHandles         = "handle.enumerate-handles"
	symbolPaths              = "symbol-paths"
	symbolizeKernelAddresses = "symbolize-kernel-addresses"

	serializeThreads = "event.serialize-threads"
	serializeModules = "event.serialize-modules"
	serializeHandles = "event.serialize-handles"
	serializePE      = "event.serialize-pe"
	serializeEnvs    = "event.serialize-envs"
)

type platformConfig struct {
	PE                       pe.Config      `json:"pe" yaml:"pe"`
	InitHandleSnapshot       bool           `json:"init-handle-snapshot" yaml:"init-handle-snapshot"`
	EnumerateHandles         bool           `json:"enumerate-handles" yaml:"enumerate-handles"`
	SymbolPaths              string         `json:"symbol-paths" yaml:"symbols-paths"`
	SymbolizeKernelAddresses bool           `json:"symbolize-kernel-addresses" yaml:"symbolize-kernel-addresses"`
	DebugPrivilege           bool           `json:"debug-privilege" yaml:"debug-privilege"`
	Yara                     yara.Config    `json:"yara" yaml:"yara"`
	Evasion                  evasion.Config `json:"evasion" yaml:"evasion"`
}

func newPlatformConfig() platformConfig {
	return platformConfig{
		PE:   pe.Config{},
		Yara: yara.Config{},
	}
}

func (c *Config) addPlatformFlags() {
	if c.opts.run || c.opts.replay {
		outputeventlog.AddFlags(c.flags)
		systray.AddFlags(c.flags)
		eventlog.AddFlags(c.flags)
		yara.AddFlags(c.flags)
	}
	if c.opts.run || c.opts.capture {
		pe.AddFlags(c.flags)
		c.EventSource.AddFlags(c.flags)
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

func (c *Config) initPlatform() {
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

// Validate validates the configuration file and merged Viper settings against the schema.
func (c *Config) Validate() error { return c.validateConfig() }

func defaultConfigFile() string {
	return filepath.Join(os.Getenv("PROGRAMFILES"), "fibratus", "config", "fibratus.yml")
}

func defaultFilamentPath() string {
	return filepath.Join(os.Getenv("PROGRAMFILES"), "fibratus", "filaments")
}

func defaultRulesPaths() []string {
	return []string{filepath.Join(defaultRulesDir(), "*")}
}

func defaultMacrosPaths() []string {
	return []string{filepath.Join(defaultRulesDir(), "Macros", "*")}
}

func defaultRulesDir() string {
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
