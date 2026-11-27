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

package eval

import (
	"github.com/rabbitstack/fibratus/internal/evasion"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// missingEnv is what an environment variable that doesn't exist reads as:
// no value.
func missingEnv() (any, bool) { return nil, false }

// platformEvaluator returns the evaluator of the fields that are read on Windows
// and aren't shared with the other platforms, or nil if the field isn't one of them.
func platformEvaluator(f Field) Evaluator {
	for _, get := range []func(Field) Evaluator{
		processEvaluator,
		moduleEvaluator,
		peEvaluator,
		threadEvaluator,
		fileEvaluator,
		registryEvaluator,
		networkEvaluator,
		memoryEvaluator,
		dnsEvaluator,
	} {
		if ev := get(f); ev != nil {
			return ev
		}
	}
	switch f.Name {
	case fields.EvtIsDirectSyscall:
		return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) bool {
			return e.Evasions&uint32(evasion.DirectSyscall) != 0
		})}
	case fields.EvtIsIndirectSyscall:
		return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) bool {
			return e.Evasions&uint32(evasion.IndirectSyscall) != 0
		})}
	}
	return nil
}
