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

package eval

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkSequenceExpr(t *testing.T) {
	var tests = []struct {
		expression string
		assertions func(*testing.T, *Evaluator)
	}{
		{`sequence 
	maxspan 2s
	by ps.uuid
	|evt.name = 'CreateProcess'|
	|evt.name = 'CreateFile'|`, func(tt *testing.T, eval *Evaluator) {
			assert.Len(t, eval.GetFields(), 2)
		}},
		{`sequence 
	maxspan 2s
	by ps.uuid, file.object
	|evt.name = 'CreateProcess' and ps.name = 'explorer.exe'|
	|evt.name = 'CreateFile'|`, func(tt *testing.T, eval *Evaluator) {
			assert.Len(t, eval.GetFields(), 4)
		}},
		{`sequence 
	maxspan 2s
	|evt.name = 'CreateProcess'| by ps.exe
	|evt.name = 'CreateFile'| by file.path`, func(tt *testing.T, eval *Evaluator) {
			assert.Len(t, eval.GetFields(), 3)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.expression, func(t *testing.T) {
			eval, err := NewEvaluator(uuid.New().String(), tt.expression)
			require.NoError(t, err)
			tt.assertions(t, eval)
		})
	}
}
