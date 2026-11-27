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

//go:build yara

package eval

import (
	"fmt"
	"strings"
	"time"

	"github.com/hillu/go-yara/v4"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
)

// scanTimeout specifies the timeout interval for the scan operation
var scanTimeout = time.Second * 10

// YaraEvaluator evaluates the yara function, which provides signature-based
// detection in the filters and the rules. Depending on the type of the target,
// the scan is performed on the process (a pid), the file (a file name) or the
// memory block (the bytes).
type YaraEvaluator struct {
	EvaluatorBase
	Target, Rules Evaluator
	// Vars are the variables the rules are compiled with. It is nil if there are none.
	Vars Evaluator
}

func newYaraEvaluator(args []Evaluator) (Evaluator, error) {
	return &YaraEvaluator{
		EvaluatorBase: EvaluatorBase{Expensive: true},
		Target:        args[0],
		Rules:         args[1],
		Vars:          optionalArg(args, 2),
	}, nil
}

func (e *YaraEvaluator) Eval(ctx *EvalCtx) any {
	var rules string
	switch r := e.Rules.Eval(ctx).(type) {
	case string:
		rules = r
	case []string:
		rules = strings.Join(r, " ")
	}
	var vars map[string]any
	if e.Vars != nil {
		vars, _ = e.Vars.Eval(ctx).(map[string]any)
	}
	scanner, err := newScanner(rules, vars)
	if err != nil {
		log.Warnf("erroneous scanner in YARA function: %v: %s", err, rules)
		return false
	}

	var cb yara.MatchRules
	switch n := e.Target.Eval(ctx).(type) {
	case uint32: // pid
		err = scanner.SetCallback(&cb).ScanProc(int(n))
	case string: // file
		err = scanner.SetCallback(&cb).ScanFile(n)
	case []byte: // mem block
		err = scanner.SetCallback(&cb).ScanMem(n)
	default: // invalid type
		return false
	}
	if err != nil {
		log.Warnf("YARA function scan failed: %v", err)
		return false
	}
	if len(cb) > 0 {
		log.Debugf("YARA function produced %d match(es)", len(cb))
		for _, match := range cb {
			log.Debugf("Matched YARA rule: %s", match.Rule)
		}
	}
	return len(cb) > 0
}

func newScanner(rules string, vars map[string]any) (*yara.Scanner, error) {
	c, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}
	if err := c.AddString(rules, ""); err != nil {
		return nil, err
	}
	for k, v := range vars {
		if err := c.DefineVariable(k, v); err != nil {
			return nil, err
		}
	}
	if len(c.Errors) > 0 {
		return nil, parseCompilerErrors(c.Errors)
	}
	r, err := c.GetRules()
	if err != nil {
		return nil, err
	}
	scanner, err := yara.NewScanner(r)
	if err != nil {
		return nil, err
	}
	scanner.SetFlags(yara.ScanFlagsFastMode)
	scanner.SetTimeout(scanTimeout)
	return scanner, nil
}

func parseCompilerErrors(errors []yara.CompilerMessage) error {
	errs := make([]error, len(errors))
	for i, err := range errors {
		errs[i] = fmt.Errorf("%s, line: %d", err.Text, err.Line)
	}
	return multierror.Wrap(errs...)
}
