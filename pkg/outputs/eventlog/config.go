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
	"fmt"

	"github.com/rabbitstack/fibratus/pkg/outputs"
)

// Level is the type definition for the eventlog log level
type Level uint16

const (
	// Info represents the info log level
	Info Level = 4
	// Warn represents the warning info level
	Warn Level = 2
	// Erro represents the error log level
	Erro Level = 1
)

func levelFromString(s string) Level {
	switch s {
	case "info", "INFO":
		return Info
	case "warn", "warning", "WARN", "WARNING":
		return Warn
	case "erro", "error", "ERRO", "ERROR":
		return Erro
	default:
		panic(fmt.Sprintf("unrecognized evtlog level: %s", s))
	}
}

// Config contains configuration properties for fine-tuning the eventlog output.
type Config struct {
	Enabled    bool               `mapstructure:"enabled"`
	Serializer outputs.Serializer `mapstructure:"serializer"`
	Level      string             `mapstructure:"level"`
	RemoteHost string             `mapstructure:"remote-host"`
}
