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

package ql

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSequenceExprIsEvaluable(t *testing.T) {
	var tests = []struct {
		expr       string
		evt        *event.Event
		isEval     bool
		assertions func(t *testing.T, sexpr *SequenceExpr)
	}{
		{"evt.name = 'CreateProcess'", &event.Event{Type: event.CreateProcess, Category: event.Process}, true,
			func(t *testing.T, sexpr *SequenceExpr) {
				assert.True(t, sexpr.bitsets.IsInitialized(event.TypeBitSet))
				assert.False(t, sexpr.bitsets.IsInitialized(event.BitmaskBitSet))
				assert.False(t, sexpr.bitsets.IsInitialized(event.CategoryBitSet))
			},
		},
		{"evt.name = 'CreateProcess'", &event.Event{Type: event.TerminateProcess, Category: event.Process}, false, nil},
		{"evt.name = 'CreateProcess' or evt.name = 'TerminateThread'", &event.Event{Type: event.TerminateProcess, Category: event.Process}, false, nil},
		{"evt.name = 'CreateProcess' or evt.category = 'object'", &event.Event{Type: event.TerminateProcess, Category: event.Process}, false, nil},
		{"evt.name = 'CreateProcess' or evt.name = 'OpenProcess'", &event.Event{Type: event.OpenProcess, Category: event.Process}, true,
			func(t *testing.T, sexpr *SequenceExpr) {
				assert.True(t, sexpr.bitsets.IsInitialized(event.TypeBitSet))
				assert.False(t, sexpr.bitsets.IsInitialized(event.BitmaskBitSet))
				assert.False(t, sexpr.bitsets.IsInitialized(event.CategoryBitSet))
			},
		},
		{"evt.name = 'CreateProcess' or evt.name = 'CreateThread'", &event.Event{Type: event.CreateThread, Category: event.Thread}, true,
			func(t *testing.T, sexpr *SequenceExpr) {
				assert.False(t, sexpr.bitsets.IsInitialized(event.TypeBitSet))
				assert.True(t, sexpr.bitsets.IsInitialized(event.BitmaskBitSet))
				assert.False(t, sexpr.bitsets.IsInitialized(event.CategoryBitSet))
			},
		},
		{"evt.name = 'CreateProcess' or evt.category = 'registry'", &event.Event{Type: event.RegSetValue, Category: event.Registry}, true,
			func(t *testing.T, sexpr *SequenceExpr) {
				assert.True(t, sexpr.bitsets.IsInitialized(event.TypeBitSet))
				assert.False(t, sexpr.bitsets.IsInitialized(event.BitmaskBitSet))
				assert.True(t, sexpr.bitsets.IsInitialized(event.CategoryBitSet))
			},
		},
		{"evt.name = 'CreateProcess' or evt.name = 'OpenProcess' or evt.category = 'registry'", &event.Event{Type: event.OpenProcess, Category: event.Process}, true,
			func(t *testing.T, sexpr *SequenceExpr) {
				assert.True(t, sexpr.bitsets.IsInitialized(event.TypeBitSet))
				assert.False(t, sexpr.bitsets.IsInitialized(event.BitmaskBitSet))
				assert.True(t, sexpr.bitsets.IsInitialized(event.CategoryBitSet))
			},
		},
		{"evt.name = 'CreateProcess' or evt.name = 'SetThreadContext' or evt.category = 'registry'", &event.Event{Type: event.CreateProcess, Category: event.Process}, true,
			func(t *testing.T, sexpr *SequenceExpr) {
				assert.False(t, sexpr.bitsets.IsInitialized(event.TypeBitSet))
				assert.True(t, sexpr.bitsets.IsInitialized(event.BitmaskBitSet))
				assert.True(t, sexpr.bitsets.IsInitialized(event.CategoryBitSet))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			p := NewParser(tt.expr)
			expr, err := p.ParseExpr()
			require.NoError(t, err)

			sexpr := &SequenceExpr{Expr: expr}
			sexpr.init()
			sexpr.walk()

			assert.Equal(t, tt.isEval, sexpr.IsEvaluable(tt.evt))
			if tt.assertions != nil {
				tt.assertions(t, sexpr)
			}
		})
	}
}
