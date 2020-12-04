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

package rotate

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
	"io"
	"runtime"
	"strings"
)

// Config is the configuration for the rotate file hook.
type Config struct {
	Filename   string
	MaxSize    int
	MaxBackups int
	MaxAge     int
	Level      logrus.Level
	Formatter  logrus.Formatter
}

// File represents the rotate file hook.
type File struct {
	config       Config
	w            io.Writer
	depth        int
	skip         int
	formatter    func(file, function string, line int) string
	skipPrefixes []string
}

// NewHook builds a new rotate file hook.
func NewHook(config Config) (logrus.Hook, error) {
	hook := File{
		config:       config,
		depth:        20,
		skip:         5,
		skipPrefixes: []string{"logrus/", "logrus@"},
		formatter: func(file, function string, line int) string {
			return fmt.Sprintf("%s:%d", file, line)
		},
	}
	hook.w = &lumberjack.Logger{
		Filename:   config.Filename,
		MaxSize:    config.MaxSize,
		MaxBackups: config.MaxBackups,
		MaxAge:     config.MaxAge,
	}
	return &hook, nil
}

// Levels determines log levels that for which the logs are written.
func (hook *File) Levels() []logrus.Level {
	return logrus.AllLevels[:hook.config.Level+1]
}

// Fire is called by logrus when it is about to write the log entry.
func (hook *File) Fire(entry *logrus.Entry) (err error) {
	modified := entry.WithField("source", hook.formatter(hook.findCaller()))
	modified.Level = entry.Level
	modified.Message = entry.Message
	b, err := hook.config.Formatter.Format(modified)
	if err != nil {
		return err
	}
	_, err = hook.w.Write(b)
	return err
}

func (hook *File) findCaller() (string, string, int) {
	var (
		pc       uintptr
		file     string
		function string
		line     int
	)
	for i := 0; i < hook.depth; i++ {
		pc, file, line = getCaller(hook.skip + i)
		if !hook.skipFile(file) {
			break
		}
	}
	if pc != 0 {
		frames := runtime.CallersFrames([]uintptr{pc})
		frame, _ := frames.Next()
		function = frame.Function
	}

	return file, function, line
}

func (hook *File) skipFile(file string) bool {
	for i := range hook.skipPrefixes {
		if strings.HasPrefix(file, hook.skipPrefixes[i]) {
			return true
		}
	}
	return false
}

func getCaller(skip int) (uintptr, string, int) {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return 0, "", 0
	}

	n := 0
	for i := len(file) - 1; i > 0; i-- {
		if file[i] == '/' {
			n++
			if n >= 2 {
				file = file[i+1:]
				break
			}
		}
	}

	return pc, file, line
}
