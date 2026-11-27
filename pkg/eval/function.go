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
	"fmt"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/functions"
	log "github.com/sirupsen/logrus"
)

// The functions of the rule language are evaluators too. A function is compiled
// into an evaluator in the way a field is, except that the field evaluator reads
// a value from the event, and the function evaluator computes a value from the
// evaluators of its arguments, which are the fields, the literals and other
// function calls. The evaluators of the functions have the type of the
// function, e.g. LowerStringEvaluator, CIDREvaluator, or ForeachEvaluator, and
// are grouped in the files by what they work on:
//
//   - string.go: the string functions, e.g. lower, upper, split or replace
//   - regex.go: the regular expression function
//   - cidr.go: the CIDR function
//   - path.go: the file path functions, e.g. base, dir or ext
//   - sys.go: the functions that query the system, e.g. get_reg_value
//   - yara.go: the YARA function
//   - collection.go: the foreach function
//
// A function that can't compute its value returns the undefined value of the
// call: false for a call that is missing the arguments it needs, and nil if
// there is nothing to return.

// minArgs is the number of the arguments the function can't be called without.
// The parser has validated the call, so it is only a safeguard of the
// constructors.
var minArgs = map[functions.Fn]int{
	functions.CIDRContainsFn: 2,
	functions.MD5Fn:          1,
	functions.ConcatFn:       2,
	functions.LtrimFn:        2,
	functions.RtrimFn:        2,
	functions.LowerFn:        1,
	functions.UpperFn:        1,
	functions.ReplaceFn:      3,
	functions.SplitFn:        2,
	functions.LengthFn:       1,
	functions.IndexOfFn:      2,
	functions.SubstrFn:       2,
	functions.EntropyFn:      1,
	functions.RegexFn:        2,
	functions.BaseFn:         1,
	functions.DirFn:          1,
	functions.SymlinkFn:      1,
	functions.ExtFn:          1,
	functions.GlobFn:         1,
	functions.IsAbsFn:        1,
	functions.VolumeFn:       1,
	functions.YaraFn:         2,
	functions.CountFn:        2,
	functions.GetRegValueFn:  1,
	functions.IsMinidumpFn:   1,
}

// compileFunction compiles the function call into the evaluator of the
// function. The arguments of the call are compiled first, and the foreach
// function takes its arguments apart on its own, since two of them are the
// predicate and the variable that it binds, not the values.
func compileFunction(expr *ast.Function, x *extractor) Evaluator {
	fn, ok := functions.Parse(expr.Name)
	if !ok {
		log.Warnf("undefined function %s", expr.Name)
		return &ConstEvaluator{}
	}
	var (
		ev  Evaluator
		err error
	)
	if fn == functions.ForeachFn {
		ev, err = newForeach(expr, x)
	} else {
		args := make([]Evaluator, len(expr.Args))
		for i, arg := range expr.Args {
			args[i] = compileNode(arg, x)
		}
		ev, err = newFunction(fn, args)
	}
	if err != nil {
		log.Warnf("unable to compile %s function: %v", expr.Name, err)
		return &ConstEvaluator{}
	}
	return ev
}

// newFunction returns the evaluator of the function that is called with the
// arguments. It is the counterpart of GetEvaluator for the functions, and
// there is no registry behind it either.
func newFunction(fn functions.Fn, args []Evaluator) (Evaluator, error) {
	if n := minArgs[fn]; len(args) < n {
		return nil, fmt.Errorf("%s function requires %d argument(s) but %d argument(s) given", fn, n, len(args))
	}
	base := EvaluatorBase{}
	switch fn {
	// string functions
	case functions.LowerFn:
		return &LowerStringEvaluator{EvaluatorBase: base, Arg: args[0]}, nil
	case functions.UpperFn:
		return &UpperStringEvaluator{EvaluatorBase: base, Arg: args[0]}, nil
	case functions.LtrimFn:
		return &LtrimEvaluator{EvaluatorBase: base, Str: args[0], Prefix: args[1]}, nil
	case functions.RtrimFn:
		return &RtrimEvaluator{EvaluatorBase: base, Str: args[0], Suffix: args[1]}, nil
	case functions.ReplaceFn:
		return &ReplaceEvaluator{EvaluatorBase: base, Str: args[0], Replacements: args[1:]}, nil
	case functions.SplitFn:
		return &SplitEvaluator{EvaluatorBase: base, Str: args[0], Sep: args[1]}, nil
	case functions.SubstrFn:
		return &SubstrEvaluator{EvaluatorBase: base, Str: args[0], Start: args[1], End: optionalArg(args, 2)}, nil
	case functions.IndexOfFn:
		return &IndexOfEvaluator{EvaluatorBase: base, Str: args[0], Substr: args[1], Order: optionalArg(args, 2)}, nil
	case functions.LengthFn:
		return &LengthEvaluator{EvaluatorBase: base, Arg: args[0]}, nil
	case functions.ConcatFn:
		return &ConcatEvaluator{EvaluatorBase: base, Args: args}, nil
	case functions.MD5Fn:
		if len(args) != 1 {
			return &ConstEvaluator{Value: false}, nil
		}
		return &MD5Evaluator{EvaluatorBase: base, Arg: args[0]}, nil
	case functions.EntropyFn:
		return &EntropyEvaluator{EvaluatorBase: base, Str: args[0], Algo: optionalArg(args, 1)}, nil
	case functions.CountFn:
		return &CountEvaluator{EvaluatorBase: base, Str: args[0], Pattern: args[1], CaseInsensitive: optionalArg(args, 2)}, nil
	// regular expressions
	case functions.RegexFn:
		return newRegexEvaluator(args), nil
	// networking
	case functions.CIDRContainsFn:
		return newCIDREvaluator(args), nil
	// file paths
	case functions.BaseFn:
		return &BaseEvaluator{EvaluatorBase: base, Path: args[0], Ext: optionalArg(args, 1)}, nil
	case functions.DirFn:
		return &DirEvaluator{EvaluatorBase: base, Path: args[0]}, nil
	case functions.ExtFn:
		return &ExtEvaluator{EvaluatorBase: base, Path: args[0], Dot: optionalArg(args, 1)}, nil
	case functions.GlobFn:
		return &GlobEvaluator{EvaluatorBase: EvaluatorBase{Expensive: true}, Pattern: args[0]}, nil
	case functions.IsAbsFn:
		return &IsAbsEvaluator{EvaluatorBase: base, Path: args[0]}, nil
	case functions.VolumeFn:
		return &VolumeEvaluator{EvaluatorBase: base, Path: args[0]}, nil
	case functions.SymlinkFn:
		return &SymlinkEvaluator{EvaluatorBase: EvaluatorBase{Expensive: true}, Path: args[0]}, nil
	case functions.YaraFn:
		return newYaraEvaluator(args)
	}
	if ev := newSysFunction(fn, args); ev != nil {
		return ev, nil
	}
	return nil, fmt.Errorf("%s function is not supported", strings.ToLower(fn.String()))
}

// optionalArg returns the argument at the position, or nil if the call doesn't have it.
func optionalArg(args []Evaluator, i int) Evaluator {
	if i < len(args) {
		return args[i]
	}
	return nil
}

// strArg returns the value of the argument if it is a string. Any other
// value, or the missing argument, is the empty string.
func strArg(ctx *EvalCtx, arg Evaluator) string {
	if arg == nil {
		return ""
	}
	s, _ := arg.Eval(ctx).(string)
	return s
}

// boolean returns the value of the argument if it is a bool, and tells if it was.
func boolean(ctx *EvalCtx, arg Evaluator) (value bool, ok bool) {
	if arg == nil {
		return false, false
	}
	value, ok = arg.Eval(ctx).(bool)
	return
}

// constString returns the string the argument always evaluates to, if
// the argument is a string literal.
func constString(arg Evaluator) (string, bool) {
	c, ok := arg.(*ConstEvaluator)
	if !ok {
		return "", false
	}
	s, ok := c.Value.(string)
	return s, ok
}
