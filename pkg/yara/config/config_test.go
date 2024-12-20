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

package config

import (
	"errors"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	ytypes "github.com/rabbitstack/fibratus/pkg/yara/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestShouldSkipProcess(t *testing.T) {
	var tests = []struct {
		c    Config
		proc string
		skip bool
	}{
		{
			Config{ExcludedProcesses: []string{"C:\\Windows\\System32\\svchost.exe"}},
			"C:\\Windows\\System32\\svchost.exe",
			true,
		},
		{
			Config{ExcludedProcesses: []string{"?:\\Windows\\System32\\svchost.exe"}},
			"C:\\Windows\\System32\\svchost.exe",
			true,
		},
		{
			Config{ExcludedProcesses: []string{"?:\\Windows\\*\\svchost.exe"}},
			"C:\\WINDOWS\\System32\\svchost.exe",
			true,
		},
		{
			Config{ExcludedProcesses: []string{"?:\\Windows\\*\\*.exe"}},
			"C:\\Windows\\System32\\svchost.exe",
			true,
		},
		{
			Config{ExcludedProcesses: []string{"?:\\Windows\\*\\*.exe"}},
			"C:\\Windows\\hh.exe",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.proc, func(t *testing.T) {
			assert.Equal(t, tt.skip, tt.c.ShouldSkipProcess(tt.proc))
		})
	}
}

func TestShouldSkipFile(t *testing.T) {
	var tests = []struct {
		c    Config
		file string
		skip bool
	}{
		{
			Config{ExcludedFiles: []string{"C:\\Windows\\System32\\svchost.exe"}},
			"C:\\Windows\\System32\\svchost.exe",
			true,
		},
		{
			Config{ExcludedFiles: []string{"?:\\Windows\\System32\\svchost.exe", "?:\\Program Files\\*\\*.exe"}},
			"C:\\Program Files\\dotnet\\dotnet.exe",
			true,
		},
		{
			Config{ExcludedFiles: []string{"?:\\Windows\\*\\svchost.exe"}},
			"C:\\Program Files\\dotnet\\dotnet.exe",
			false,
		},
		{
			Config{ExcludedFiles: []string{"?:\\Windows\\*\\*.exe", "C:\\Program Files\\Logs\\*\\*.dll"}},
			"C:\\Program Files\\dotnet\\sdk\\8.0.300\\Microsoft.build.dll",
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			assert.Equal(t, tt.skip, tt.c.ShouldSkipFile(tt.file))
		})
	}
}

func TestAlertTitle(t *testing.T) {
	var tests = []struct {
		e *kevent.Kevent
		t string
	}{
		{
			&kevent.Kevent{Type: ktypes.MapViewFile, Category: ktypes.File},
			MemoryThreatAlertTitle,
		},
		{
			&kevent.Kevent{Type: ktypes.MapViewFile, Category: ktypes.File,
				Kparams: kevent.Kparams{kparams.FilePath: {Name: kparams.FilePath, Type: kparams.UnicodeString, Value: "C:\\Windows\\System32\\wusa.exe"}},
			},
			FileThreatAlertTitle,
		},
		{
			&kevent.Kevent{Type: ktypes.RegSetValue, Category: ktypes.Registry},
			FileThreatAlertTitle,
		},
		{
			&kevent.Kevent{Type: ktypes.LoadImage, Category: ktypes.Image},
			MemoryThreatAlertTitle,
		},
	}

	for _, tt := range tests {
		t.Run(tt.t, func(t *testing.T) {
			c := Config{}
			assert.Equal(t, tt.t, c.AlertTitle(tt.e))
		})
	}
}

func TestAlertText(t *testing.T) {
	var tests = []struct {
		name string
		c    Config
		e    *kevent.Kevent
		m    ytypes.MatchRule
		text string
		err  error
	}{
		{
			"empty template and no threat_name meta",
			Config{},
			&kevent.Kevent{Type: ktypes.LoadImage, Category: ktypes.Image},
			ytypes.MatchRule{Rule: "Badlands Trojan"},
			"Threat detected Badlands Trojan",
			nil,
		},
		{
			"empty template and threat_name meta",
			Config{},
			&kevent.Kevent{Type: ktypes.LoadImage, Category: ktypes.Image},
			ytypes.MatchRule{Rule: "Badlands Trojan", Metas: []ytypes.Meta{{Identifier: "threat_name", Value: "Gravity Trojan"}}},
			"Threat detected Gravity Trojan",
			nil,
		},
		{
			"template given in config",
			Config{
				AlertTemplate: `
				Rule name: {{ .Match.Rule }}
				Event name: {{ .Event.Name -}}
				`,
			},
			&kevent.Kevent{Type: ktypes.LoadImage, Name: "LoadImage", Category: ktypes.Image},
			ytypes.MatchRule{Rule: "Badlands Trojan", Metas: []ytypes.Meta{{Identifier: "threat_name", Value: "Gravity Trojan"}}},
			`
				Rule name: Badlands Trojan
				Event name: LoadImage`,
			nil,
		},
		{
			"invalid template given in config",
			Config{
				AlertTemplate: `
				Rule name: {{ .....Match.Rule }}
				Event name: {{ .Evet.Name -}}
				`,
			},
			&kevent.Kevent{Type: ktypes.LoadImage, Name: "LoadImage", Category: ktypes.Image},
			ytypes.MatchRule{Rule: "Badlands Trojan", Metas: []ytypes.Meta{{Identifier: "threat_name", Value: "Gravity Trojan"}}},
			"",
			errors.New("yara alert template syntax error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, err := tt.c.AlertText(tt.e, tt.m)
			if tt.err != nil && err == nil {
				require.Error(t, tt.err)
			}
			assert.Equal(t, tt.text, text)
		})
	}
}
