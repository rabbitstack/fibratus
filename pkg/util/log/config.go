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

package log

import (
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	logLevel      = "logging.level"
	logMaxAge     = "logging.max-age"
	logMaxBackups = "logging.max-backups"
	logMaxSize    = "logging.max-size"
	logFormatter  = "logging.formatter"
	logPath       = "logging.path"
	logStdout     = "logging.log-stdout"
)

// Config contains a set of setting that control the behaviour of the logging system.
type Config struct {
	// Level specifies the minimum allowed log level.
	Level string `json:"logging.level" yaml:"logging.level"`
	// MaxAge is the maximum number of days to retain old log files based on the
	// timestamp encoded in their filename.
	MaxAge int `json:"logging.max-age" yaml:"logging.max-age"`
	// MaxBackups is the maximum number of old log files to retain.
	MaxBackups int `json:"logging.max-backups" yaml:"logging.max-backups"`
	// MaxSize is the maximum size in megabytes of the log file before it gets rotated.
	MaxSize int `json:"logging.max-size" yaml:"logging.max-size"`
	// Formatter represents the log formatter (json | text ).
	Formatter string `json:"logging.formatter" yaml:"logging.formatter"`
	// Path represents the alternative paths for storing the logs.
	Path string `json:"logging.path" yaml:"logging.path"`
	// LogStdout indicates whether log lines are written to standard output in addition to writing them
	// to log files.
	LogStdout bool `json:"logging.log-stdout" yaml:"logging.log-stdout"`
}

// InitFromViper initializes logging configuration from Viper.
func (c *Config) InitFromViper(v *viper.Viper) {
	c.Level = v.GetString(logLevel)
	c.MaxAge = v.GetInt(logMaxAge)
	c.MaxBackups = v.GetInt(logMaxBackups)
	c.MaxSize = v.GetInt(logMaxSize)
	c.Formatter = v.GetString(logFormatter)
	c.Path = v.GetString(logPath)
	c.LogStdout = v.GetBool(logStdout)
}

// AddFlags registers persistent logging flags.
func (c *Config) AddFlags(flags *pflag.FlagSet) {
	flags.String(logLevel, "info", "Specifies the minimum allowed log level")
	flags.Int(logMaxAge, 0, "Sets he maximum number of days to retain old log files based on the timestamp encoded in their filename. By default no old log files will be removed")
	flags.Int(logMaxBackups, 15, "Specifies the maximum number of old log files to retain")
	flags.Int(logMaxSize, 100, "Specifies the maximum size in megabytes of the log file before it gets rotated")
	flags.String(logFormatter, "json", "Represents the log formatter (json|text )")
	flags.String(logPath, "", "Specifies the alternative paths for storing the logs")
	flags.Bool(logStdout, false, "Indicates whether log lines are written to standard output in addition to writing them to log files")
}
