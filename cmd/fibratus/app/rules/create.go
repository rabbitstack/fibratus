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

package rules

import (
	"fmt"
	"github.com/enescakir/emoji"
	"github.com/google/uuid"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/util/version"
	"os"
	"strings"
	"text/template"
)

var ruleTemplate = `name: {{ .Name }}
id: {{ .ID }}
version: {{ .Version }}
description: |
  Provide a meaningful description that clearly conveys the detection objectives of this rule.
  Good descriptions usually start with "Identifies ..." or "Detects ...".
{{- if .Labels }}
labels:
{{- range $key, $value := .Labels }}
  {{ $key }}: {{ $value }}
{{- end -}}
{{ end }}

condition: >

min-engine-version: {{ .MinEngineVersion }}
`
var tactics = map[string]string{
	"TA0001": "Initial Access",
	"TA0002": "Execution",
	"TA0003": "Persistence",
	"TA0004": "Privilege Escalation",
	"TA0005": "Defense Evasion",
	"TA0006": "Credential Access",
	"TA0007": "Discovery",
	"TA0008": "Lateral Movement",
	"TA0009": "Collection",
	"TA0011": "Command and Control",
	"TA0040": "Impact",
	"TA0042": "Resource Development",
	"TA0043": "Reconnaissance",
}

func createRule(name string) error {
	data := struct {
		*config.FilterConfig
		MinEngineVersion string
	}{
		&config.FilterConfig{
			Name:    name,
			ID:      uuid.New().String(),
			Version: "1.0.0",
		},
		version.Get(),
	}

	if tacticID != "" {
		data.Labels = make(map[string]string)
		data.Labels["tactic.id"] = tacticID
		data.Labels["tactic.name"] = tactics[tacticID]
		data.Labels["tactic.ref"] = fmt.Sprintf("https://attack.mitre.org/tactics/%s/", tacticID)
	}

	tmpl, err := template.New("rule").Parse(ruleTemplate)
	if err != nil {
		return err
	}

	n := fmt.Sprintf("%s.yml", strings.ReplaceAll(strings.ToLower(name), " ", "_"))
	if tacticID != "" {
		n = strings.ReplaceAll(strings.ToLower(tactics[tacticID]), " ", "_") + "_" + n
	}
	f, err := os.Create(n)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := tmpl.Execute(f, data); err != nil {
		return err
	}

	emo("%v created %s. Open the file and craft the rule condition, define an optional action, or fill out other attributes", emoji.Rocket, n)

	return nil
}
