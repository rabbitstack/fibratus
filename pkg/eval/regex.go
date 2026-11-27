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
	"regexp"

	log "github.com/sirupsen/logrus"
)

// RegexEvaluator evaluates the regex function, which tells whether the string
// matches any of the regular expressions. The expressions are literals, so they
// are compiled once with the function, and not for every event. An expression
// that doesn't compile is reported when the function is compiled, and
// never matches.
type RegexEvaluator struct {
	EvaluatorBase
	Str Evaluator
	// Regexps are the compiled expressions.
	Regexps []*regexp.Regexp
}

func newRegexEvaluator(args []Evaluator) *RegexEvaluator {
	e := &RegexEvaluator{Str: args[0]}
	for _, arg := range args[1:] {
		expr, ok := constString(arg)
		if !ok {
			continue
		}
		rx, err := regexp.Compile(expr)
		if err != nil {
			log.Warnf("invalid %q pattern in regex function: %v", expr, err)
			continue
		}
		e.Regexps = append(e.Regexps, rx)
	}
	return e
}

func (e *RegexEvaluator) Eval(ctx *EvalCtx) any {
	s := strArg(ctx, e.Str)
	for _, rx := range e.Regexps {
		if rx.MatchString(s) {
			return true
		}
	}
	return false
}
