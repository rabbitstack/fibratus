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

package mail

import (
	"bytes"
	"github.com/Masterminds/sprig/v3"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/util/hostname"
	"github.com/rabbitstack/fibratus/pkg/util/version"
	"text/template"
	"time"
)

// renderHTMLTemplate produces HTML template for the alert.
// This function generates inlined CSS to maximize the compatibility
// across email clients.
func renderHTMLTemplate(alert alertsender.Alert) (string, error) {
	data := struct {
		Alert       alertsender.Alert
		TriggeredAt time.Time
		Hostname    string
		Version     string
	}{
		alert,
		time.Now(),
		hostname.Get(),
		version.Get(),
	}

	_ = data.Alert.MDToHTML()
	funcmap := sprig.TxtFuncMap()

	// redefine hasKey to work on string map values
	funcmap["hasKey"] = func(m map[string]string, key string) bool {
		if _, ok := m[key]; ok {
			return true
		}
		return false
	}
	tmpl, err := template.New("alert").Funcs(funcmap).Parse(htmlTemplate)
	if err != nil {
		return "", err
	}

	var bb bytes.Buffer
	if err := tmpl.Execute(&bb, data); err != nil {
		return "", err
	}
	return bb.String(), nil
}
