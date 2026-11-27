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
	"strings"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

// This file holds the process fields that both platforms read the same way.
// The rest of the process fields is read by the evaluators of the platform files.

// getParentPs returns the process state of the parent process, if known.
func getParentPs(e *event.Event) *pstypes.PS {
	if e.PS == nil {
		return nil
	}
	return e.PS.Parent
}

// envsSlot is the slot of the memoized environment variables
var envsSlot = new(byte)

// envs returns the environment variables as name:value pairs.
func envs(ctx *EvalCtx, ps *pstypes.PS) []string {
	return memoized(ctx, envsSlot, ps, func() []string {
		envs := make([]string, 0, len(ps.Envs))
		for k, v := range ps.Envs {
			envs = append(envs, k+":"+v)
		}
		return envs
	})
}

// envValue returns a single environment variable, by its name or by the
// prefix of the name, as ps.envs[winroot] does.
func envValue(ps *pstypes.PS, name string) (string, bool) {
	if v, ok := ps.Envs[name]; ok {
		return v, true
	}
	for k, v := range ps.Envs {
		if strings.HasPrefix(k, name) {
			return v, true
		}
	}
	return "", false
}

// sharedProcessEvaluator returns the evaluator of the process fields that have
// the same meaning on every platform, or nil if the field isn't one of them. A ps.*
// field and its ps.parent.* twin are read by the same evaluator, that reads the
// property from the process the field refers to.
func sharedProcessEvaluator(f Field) Evaluator {
	ps := processOf(f)
	switch f.Name {
	case fields.PsName, fields.PsParentName:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) string { return p.Name })}
	case fields.PsCmdline, fields.PsParentCmdline:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) string { return p.Cmdline })}
	case fields.PsExe, fields.PsParentExe:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) string { return p.Exe })}
	case fields.PsArgs, fields.PsParentArgs:
		return &StringSliceEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) []string { return p.Args })}
	case fields.PsCwd, fields.PsParentCwd:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) string { return p.Cwd })}
	case fields.PsUsername, fields.PsParentUsername:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) string { return p.Username })}
	case fields.PsUUID, fields.PsParentUUID:
		return &Uint64Evaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) uint64 { return p.UUID() })}

	case fields.PsPid:
		return &Uint32Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint32 { return e.PID })}
	case fields.PsPpid:
		return &Uint32Evaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) uint32 { return p.Ppid })}
	case fields.PsParentPid:
		return &Uint32Evaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) uint32 { return p.PID })}

	case fields.PsEnvs:
		// ps.envs[name] is a single variable, and ps.envs is all of them
		arg := f.Arg
		return &AnyEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) (any, bool) {
			ps := ctx.Evt.PS
			if ps == nil {
				return nil, false
			}
			if arg == "" {
				return envs(ctx, ps), true
			}
			if v, ok := envValue(ps, arg); ok {
				return v, true
			}
			// what a missing variable reads as is up to the platform
			return missingEnv()
		}}
	case fields.PsParentEnvs:
		// the parent has no argument form: it is always all the variables
		return &StringSliceEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) ([]string, bool) {
			p := getParentPs(ctx.Evt)
			if p == nil {
				return nil, false
			}
			return envs(ctx, p), true
		}}
	}
	return nil
}
