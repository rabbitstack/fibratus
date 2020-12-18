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

package config

import (
	"gopkg.in/yaml.v2"
	"testing"
)

func TestValidate(t *testing.T) {
	var tests = []struct {
		text  string
		valid bool
		errs  int
	}{
		{text: `aggregator:
                 flush-period: 20ms
                 flush-timeout: 1s`, valid: true},
		{text: `aggregator:
                 flush-period: 20
                 flush-timeout: 1s`, valid: false, errs: 1},
		{text: `aggregator:
                 flush-perio: 20ms
                 flush-timeout: 1`, valid: false, errs: 2},

		{text: `alertsenders:
                 mail: 
                  enabled: true
                  host: smtp.gmail.com
                  port: 465
                  user: user
                  password: pas$
                  from: from@mail.com
                  to:
                   - to@mail.com
                 slack:
                  enabled: true
                  url: https://slack.url
                  workspace: fibratus
                  channel: fibratus
                  emoji: ""`, valid: true},
		{text: `alertsenders:
                 mail: 
                  enabled: true
                  host: smtp.gmail.com
                  port: 
                  user: user
                  pass: pas$
                  from: from@mail.com
                  to:
                   - invalidmail@
                 slack:
                  enabled: true
                  url: https://slack.url
                  workspace: fibratus
                  channel: fibratus
                  emoji: ""`, valid: false, errs: 6},
		{text: `api:
                 transport: "" 
                 timeout: 1s`, valid: false, errs: 1},
	}

	for i, tt := range tests {
		var m interface{}
		err := yaml.Unmarshal([]byte(tt.text), &m)
		if err != nil {
			t.Fatal(err)
		}
		valid, errs := validate(m)
		if valid != tt.valid {
			t.Errorf("%d. valid mismatch: text=%q exp=%#v got=%#v errs=%#v", i, tt.text, tt.valid, valid, errs)
		} else if len(errs) != tt.errs {
			t.Errorf("%d. error count mismatch: text=%q exp=%#v got=%#v errs=%#v", i, tt.text, tt.errs, len(errs), errs)
		}
	}
}
