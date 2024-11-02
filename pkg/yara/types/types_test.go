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

package types

import (
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSeverityFromScore(t *testing.T) {
	var tests = []struct {
		m MatchRule
		s alertsender.Severity
	}{
		{
			MatchRule{
				Metas: []Meta{{Identifier: "score", Value: 20}},
			},
			alertsender.Normal,
		},
		{
			MatchRule{
				Metas: []Meta{{Identifier: "score", Value: 43}},
			},
			alertsender.Medium,
		},
		{
			MatchRule{
				Metas: []Meta{{Identifier: "score", Value: 70}},
			},
			alertsender.High,
		},
		{
			MatchRule{
				Metas: []Meta{{Identifier: "severity", Value: 90}},
			},
			alertsender.Critical,
		},
		{
			MatchRule{},
			alertsender.High,
		},
	}

	for _, tt := range tests {
		t.Run(tt.s.String(), func(t *testing.T) {
			assert.Equal(t, tt.s, tt.m.SeverityFromScore())
		})
	}
}
