/*
 * Copyright 2021-present by Nedim Sabic Sabic
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
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/eval"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var t0 = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func ts(offset time.Duration) time.Time { return t0.Add(offset) }

// makeEvent constructs a minimal event with the given name, timestamp, and
// flat key/value params. Param values are stored as strings for simplicity;
// real accessors coerce types as needed.
func makeEvent(name string, at time.Time, kv map[string]string) *event.Event {
	// ps := params.New()
	// for k, v := range kv {
	// 	ps.Set(k, v, params.UnicodeString)
	// }
	return &event.Event{
		Name:      name,
		Timestamp: at,
		//Params:    ps,
	}
}

func TestUnconstrainedSequenceTwoStepsMatches(t *testing.T) {
	ruleDef := policy.RuleDef{
		Condition: `
		sequence
		  maxspan 1s
		  |evt.name = 'CreateProcess'|
		  |evt.name = 'CreateFile'|
	`,
	}

	rule, err := NewRule(ruleDef)
	require.NoError(t, err)

	valuer := eval.AcquireValuerCache()
	defer valuer.Release()

	matches, ok := rule.Evaluate(makeEvent("CreateProcess", ts(0), nil), valuer)
	matches, ok = rule.Evaluate(makeEvent("CreateFile", ts(10*time.Millisecond), nil), valuer)

	assert.True(t, ok)
	require.Len(t, matches, 2)
}
