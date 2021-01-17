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
	"errors"
	"expvar"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/util/log/rotate"
	fs "github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"path/filepath"
)

var (
	// errEmptyLogsPath contains logger setup errors
	loggerErrors = expvar.NewMap("logger.errors")
)

// InitFromConfig initializes a Logrus instance from config options.
func InitFromConfig(c Config) error {
	exe, err := os.Executable()
	var path string
	if err != nil {
		path = filepath.Join(os.Getenv("PROGRAMFILES"), "fibratus", "logs")
	} else {
		path = filepath.Join(filepath.Dir(exe), "..", "logs")
	}
	if c.Path != "" {
		path = c.Path
	}
	if path == "" {
		return errors.New("got an empty logs directory path. Please make sure Fibratus is installed properly")
	}
	_, err = os.Stat(path)
	if err != nil {
		// let's create the logs directory since it doesn't exist, even though
		// this should rarely happen because Fibratus installer already creates
		// the logs directory
		if err := os.MkdirAll(path, os.ModePerm); err != nil {
			return fmt.Errorf("unable to create the %s logs directory: %v", path, err)
		}
	}

	file := filepath.Join(path, "fibratus.log")

	// setup log formatter
	var formatter logrus.Formatter
	switch c.Formatter {
	case "json":
		formatter = &logrus.JSONFormatter{}
	case "text":
		formatter = &logrus.TextFormatter{}
	default:
		formatter = &logrus.JSONFormatter{}
	}
	logrus.SetFormatter(formatter)

	level, err := logrus.ParseLevel(c.Level)
	if err != nil {
		return err
	}
	logrus.SetLevel(level)

	// disable writing to stdout
	if !c.LogStdout {
		logrus.SetOutput(ioutil.Discard)
	}

	// initialize log rotate hook
	rhook, err := rotate.NewHook(rotate.Config{
		MaxAge:     c.MaxAge,
		MaxBackups: c.MaxBackups,
		MaxSize:    c.MaxSize,
		Level:      level,
		Formatter:  formatter,
		Filename:   file,
	})

	if err != nil {
		loggerErrors.Add(err.Error(), 1)
		// failed to initialize log rotate, so we fallback on simple log hook
		var pathMap fs.PathMap = make(map[logrus.Level]string)
		for _, lvl := range logrus.AllLevels {
			pathMap[lvl] = file
		}
		logrus.AddHook(fs.NewHook(pathMap, formatter))
		logrus.Warnf("unable to initialize rotate file hook: %v", err)
		return nil
	}
	logrus.AddHook(rhook)

	return nil
}
