/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const samRuleYAML = `name: File access to SAM database
id: e3dace20-4962-4381-884e-40dcdde66626
version: 1.0.8
description: |
  Identifies access to the Security Account Manager on-disk database.
labels:
  tactic.id: TA0006
  tactic.name: Credential Access
  tactic.ref: https://attack.mitre.org/tactics/TA0006/
  technique.id: T1003
  technique.name: OS Credential Dumping
  technique.ref: https://attack.mitre.org/techniques/T1003/
  subtechnique.id: T1003.002
  subtechnique.name: Security Account Manager
  subtechnique.ref: https://attack.mitre.org/techniques/T1003/002/

condition: >
  open_file and
  file.path imatches
            (
              '?:\\WINDOWS\\SYSTEM32\\CONFIG\\SAM',
              '\\Device\\HarddiskVolumeShadowCopy*\\WINDOWS\\SYSTEM32\\CONFIG\\SAM',
              '\\??\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*\\WINDOWS\\SYSTEM32\\CONFIG\\SAM'
            ) and
  ps.exe not imatches
            (
              '?:\\Program Files\\*',
              '?:\\Program Files (x86)\\*',
              '?:\\Windows\\System32\\lsass.exe',
              '?:\\Windows\\System32\\srtasks.exe',
              '?:\\Windows\\System32\\svchost.exe',
              '?:\\Windows\\System32\\Dism.exe',
              '?:\\Windows\\System32\\vmwp.exe',
              '?:\\$WINDOWS.~BT\\Sources\\SetupHost.exe',
              '?:\\Windows\\System32\\wuauclt.exe',
              '?:\\Windows\\System32\\MRT.exe',
         	  '?:\\Windows\\Microsoft.NET\\Framework\\*\\mscorsvw.exe'
            )

min-engine-version: 3.0.0
`

const macrosYAML = `- macro: spawn_process
  expr: evt.name = 'CreateProcess'

- macro: create_thread
  expr: evt.name = 'CreateThread'

- macro: create_remote_thread
  expr: create_thread and evt.pid != 4 and evt.pid != thread.pid

- macro: open_process
  expr: evt.name = 'OpenProcess' and ps.access.status = 'Success'

- macro: web_browser_binaries
  list: [
    chrome.exe, firefox.exe, msedge.exe, iexplore.exe, opera.exe,
    brave.exe, microsoftedge.exe, chromium.exe, safari.exe, vivaldi.exe
    ]
`

func TestRuleBundleRealRuleYAML(t *testing.T) {
	bundle := NewRuleBundle()

	if err := bundle.AddRule(strings.NewReader(samRuleYAML)); err != nil {
		t.Fatalf("AddRule() error = %v", err)
	}

	if got := bundle.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}

	rules, err := bundle.Rules()
	if err != nil {
		t.Fatalf("Rules() error = %v", err)
	}

	if len(rules) != 1 {
		t.Fatalf("Rules() returned %d rules, want 1", len(rules))
	}

	if rules[0] == nil {
		t.Fatal("Rules() returned a nil rule")
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestRuleBundleRealRuleYAMLFromSource(t *testing.T) {
	bundle := NewRuleBundle()

	const source = "rules/sam.yml"

	if err := bundle.AddFrom(source, strings.NewReader(samRuleYAML)); err != nil {
		t.Fatalf("AddFrom() error = %v", err)
	}

	if bundle.Empty() {
		t.Fatal("bundle should not be empty")
	}

	if got := bundle.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestMacroBundleRealMacrosYAML(t *testing.T) {
	bundle := NewMacroBundle()

	if err := bundle.AddMacro(strings.NewReader(macrosYAML)); err != nil {
		t.Fatalf("AddMacro() error = %v", err)
	}

	if got := bundle.Len(); got != 5 {
		t.Fatalf("Len() = %d, want 5", got)
	}

	macros, err := bundle.Macros()
	if err != nil {
		t.Fatalf("Macros() error = %v", err)
	}

	if len(macros) != 5 {
		t.Fatalf("Macros() returned %d macros, want 5", len(macros))
	}

	for i, macro := range macros {
		if macro == nil {
			t.Fatalf("Macros()[%d] is nil", i)
		}
	}

	if macros[0].Expression != "evt.name = 'CreateProcess'" {
		t.Errorf("spawn_process expression = %q", macros[0].Expression)
	}

	if macros[1].Expression != "evt.name = 'CreateThread'" {
		t.Errorf("create_thread expression = %q", macros[1].Expression)
	}

	if macros[2].Expression != "create_thread and evt.pid != 4 and evt.pid != thread.pid" {
		t.Errorf("create_remote_thread expression = %q", macros[2].Expression)
	}

	if macros[3].Expression != "evt.name = 'OpenProcess' and ps.access.status = 'Success'" {
		t.Errorf("open_process expression = %q", macros[3].Expression)
	}

	wantBinaries := []string{
		"chrome.exe",
		"firefox.exe",
		"msedge.exe",
		"iexplore.exe",
		"opera.exe",
		"brave.exe",
		"microsoftedge.exe",
		"chromium.exe",
		"safari.exe",
		"vivaldi.exe",
	}

	if len(macros[4].Values) != len(wantBinaries) {
		t.Fatalf("web_browser_binaries has %d values, want %d",
			len(macros[4].Values), len(wantBinaries))
	}

	for i, want := range wantBinaries {
		if got := macros[4].Values[i]; got != want {
			t.Errorf("web_browser_binaries[%d] = %q, want %q", i, got, want)
		}
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestMacroBundleAddFromMultipleSources(t *testing.T) {
	bundle := NewMacroBundle()

	first := `- macro: spawn_process
  expr: evt.name = 'CreateProcess'
`

	second := `- macro: web_browser_binaries
  list: [chrome.exe, firefox.exe]
`

	if err := bundle.AddMacroFrom("macros/process.yml", strings.NewReader(first)); err != nil {
		t.Fatalf("AddMacroFrom(first) error = %v", err)
	}

	if err := bundle.AddMacroFrom("macros/browsers.yml", strings.NewReader(second)); err != nil {
		t.Fatalf("AddMacroFrom(second) error = %v", err)
	}

	if got := bundle.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}

	macros, err := bundle.Macros()
	if err != nil {
		t.Fatalf("Macros() error = %v", err)
	}

	if len(macros) != 2 {
		t.Fatalf("Macros() returned %d macros, want 2", len(macros))
	}

	if macros[0].Expression != "evt.name = 'CreateProcess'" {
		t.Errorf("first macro expression = %q", macros[0].Expression)
	}

	if len(macros[1].Values) != 2 {
		t.Errorf("second macro has %d values, want 2", len(macros[1].Values))
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestRuleBundleLoadDirectory(t *testing.T) {
	const rulesDir = "_fixtures/rules"

	files, err := filepath.Glob(filepath.Join(rulesDir, "*.yml"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}

	if len(files) == 0 {
		t.Fatalf("no rule YAML files found in %s", rulesDir)
	}

	bundle := NewRuleBundle()

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			t.Fatalf("Open(%q) error = %v", file, err)
		}

		err = bundle.AddFrom(file, f)
		closeErr := f.Close()

		if err != nil {
			t.Fatalf("AddFrom(%q) error = %v", file, err)
		}
		if closeErr != nil {
			t.Fatalf("Close(%q) error = %v", file, closeErr)
		}
	}

	if got := bundle.Len(); got == 0 {
		t.Fatal("expected rules to be loaded")
	}

	rules, err := bundle.Rules()
	if err != nil {
		t.Fatalf("Rules() error = %v", err)
	}

	if len(rules) != bundle.Len() {
		t.Fatalf("decoded %d rules, bundle contains %d",
			len(rules), bundle.Len())
	}

	for i, rule := range rules {
		if rule == nil {
			t.Errorf("rule at index %d is nil", i)
		}
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
