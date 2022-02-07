/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package eventlog

import (
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"golang.org/x/sys/windows/svc/eventlog"
)

// Level is the type definition for the eventlog log level
type Level int

const (
	// Info represents the info log level
	Info Level = eventlog.Info
	// Warn represents the warning info level
	Warn Level = eventlog.Warning
	// Erro represents the error log level
	Erro Level = eventlog.Error
	// Unknown is the unknown log level
	Unknown Level = -1
)

// UnmarshalYAML converts the level yaml string to the corresponding enum type.
func (l *Level) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var level string
	err := unmarshal(&level)
	if err != nil {
		return err
	}
	*l = levelFromString(level)
	return nil
}

func levelFromString(s string) Level {
	switch s {
	case "info", "INFO":
		return Info
	case "warn", "warning", "WARN", "WARNING":
		return Warn
	case "erro", "error", "ERRO", "ERROR":
		return Erro
	default:
		return Unknown
	}
}

// Config contains configuration properties for fine-tuning the eventlog output.
type Config struct {
	Serializer outputs.Serializer
	Level      Level
}
