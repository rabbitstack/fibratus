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
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/log/rotate"
	fs "github.com/rifflock/lfshook"
	"github.com/saferwall/pe/log"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"path/filepath"
)

var (
	// errEmptyLogsPath contains logger setup errors
	loggerErrors = expvar.NewMap("logger.errors")
)

// InitFromConfig initializes a Logrus instance from config options.
func InitFromConfig(c Config, filename string) error {
	exe, err := os.Executable()
	var path string
	if err != nil {
		path = filepath.Join(os.Getenv("PROGRAMFILES"), "Fibratus", "Logs")
	} else {
		path = filepath.Join(filepath.Dir(exe), "..", "Logs")
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

	file := filepath.Join(path, filename)

	// setup log formatter
	var formatter logrus.Formatter
	switch c.Formatter {
	case "json":
		formatter = &logrus.JSONFormatter{}
	case "text":
		formatter = &logrus.TextFormatter{DisableQuote: true}
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
		logrus.SetOutput(io.Discard)
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

	// redirect stderr to a file if running as Windows Service
	if sys.IsWindowsService() {
		err = redirectStderrToFile(file)
		if err != nil {
			log.Warnf("stderr redirection: %v", err)
		}
	}

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

func redirectStderrToFile(file string) error {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_SYNC|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("unable to open %s for stderr redirection: %v", file, err)
	}
	defer f.Close()
	err = windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd()))
	if err != nil {
		return fmt.Errorf("failed to redirect stderr to file: %v", err)
	}
	os.Stderr = f
	return nil
}
