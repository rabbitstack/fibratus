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
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"strconv"
)

const (
	id          = "id"
	threat      = "threat_name"
	severity    = "severity"
	score       = "score"
	description = "description"
)

// A MatchRule represents a rule successfully matched against a block
// of data.
type MatchRule struct {
	Rule      string        `json:"rule"`
	Namespace string        `json:"namespace"`
	Tags      []string      `json:"tags"`
	Metas     []Meta        `json:"metas"`
	Strings   []MatchString `json:"strings"`
}

// ID returns the identifier from the rule metadata fields.
func (m MatchRule) ID() string {
	return m.getMetaString(id)
}

// Description returns the rule description from the metadata fields.
func (m MatchRule) Description() string {
	return m.getMetaString(description)
}

// ThreatName returns the threat matching the rule signature.
func (m MatchRule) ThreatName() string {
	return m.getMetaString(threat)
}

// SeverityFromScore returns the alert severity from the numerical score
// defined in the rule meta tags. If the score tag is not defined, the
// high severity is returned.
func (m MatchRule) SeverityFromScore() alertsender.Severity {
	s := m.getMetaInt(score)
	if s == 0 {
		s = m.getMetaInt(severity)
	}
	switch {
	case s > 0 && s <= 39:
		return alertsender.Normal
	case s >= 40 && s <= 59:
		return alertsender.Medium
	case s >= 60 && s <= 79:
		return alertsender.High
	case s >= 80:
		return alertsender.Critical
	default:
		return alertsender.High
	}
}

// Labels returns all meta tags as alert labels.
func (m MatchRule) Labels() map[string]string {
	labels := make(map[string]string)
	for _, meta := range m.Metas {
		switch v := meta.Value.(type) {
		case string:
			labels[meta.Identifier] = v
		case int:
			labels[meta.Identifier] = strconv.Itoa(v)
		case bool:
			labels[meta.Identifier] = strconv.FormatBool(v)
		default:
			labels[meta.Identifier] = fmt.Sprintf("%s", v)
		}
	}
	return labels
}

func (m MatchRule) getMetaString(id string) string {
	for _, meta := range m.Metas {
		if meta.Identifier == id {
			if i, ok := meta.Value.(string); ok {
				return i
			}
		}
	}
	return ""
}

func (m MatchRule) getMetaInt(id string) int {
	for _, meta := range m.Metas {
		if meta.Identifier == id {
			if i, ok := meta.Value.(int); ok {
				return i
			}
		}
	}
	return 0
}

// A MatchString represents a string declared and matched in a rule.
type MatchString struct {
	Name   string `json:"name"`
	Base   uint64 `json:"base"`
	Offset uint64 `json:"offset"`
	Data   []byte `json:"data"`
}

// Meta represents a rule meta variable. Value can be of type string,
// int, boolean, or nil.
type Meta struct {
	Identifier string      `json:"identifier"`
	Value      interface{} `json:"value"`
}
