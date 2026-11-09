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

package filter

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/eval"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// ErrSequence signals that the filter expression is a sequence.
var ErrSequence = errors.New("sequences are not allowed in filter expressions")

type filter struct {
	evaluator *eval.Evaluator
}

// New parses the filter expression and returns the filter ready for evaluation.
func New(expr string) (Filter, error) {
	evaluator, err := eval.NewEvaluator("filter", expr)
	if err != nil {
		return nil, err
	}
	if evaluator.IsSequenceExpr() {
		return nil, ErrSequence
	}
	if len(evaluator.GetFields()) == 0 {
		return nil, errors.New("expected at least one field or operator but zero found")
	}
	return &filter{evaluator: evaluator}, nil
}

// NewFromCLI builds the filter by joining all the command line arguments
// into the filter expression. It returns a nil filter if there are no arguments.
func NewFromCLI(args []string) (Filter, error) {
	expr := strings.Join(args, " ")
	if expr == "" {
		return nil, nil
	}
	f, err := New(expr)
	if err != nil {
		return nil, fmt.Errorf("bad filter:\n%v", err)
	}
	return f, nil
}

func (f *filter) Eval(evt *event.Event) bool {
	valuer := eval.AcquireValuerCache()
	defer valuer.Release()
	return f.evaluator.Eval(evt, valuer)
}
