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
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
)

// processEvaluator returns the ps.* and ps.parent.* evaluator of the fields that
// only exist on Windows, or nil if the field isn't one of them. The fields every
// platform has are read by sharedProcessEvaluator. A ps.* field and its ps.parent.*
// twin are read by the same evaluator, see processOf.
func processEvaluator(f Field) Evaluator {
	ps := processOf(f)
	switch f.Name {
	case fields.PsComm, fields.PsParentComm:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) string { return p.Cmdline })}
	case fields.PsSID, fields.PsParentSID:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) string { return p.SID })}
	case fields.PsDomain, fields.PsParentDomain:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) string { return p.Domain })}
	case fields.PsSessionID, fields.PsParentSessionID:
		return &Uint32Evaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) uint32 { return p.SessionID })}
	case fields.PsIsWOW64Field, fields.PsParentIsWOW64Field:
		return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) bool { return p.IsWOW64 })}
	case fields.PsIsPackagedField, fields.PsParentIsPackagedField:
		return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) bool { return p.IsPackaged })}
	case fields.PsIsProtectedField, fields.PsParentIsProtectedField:
		return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) bool { return p.IsProtected })}
	case fields.PsTokenIntegrityLevel, fields.PsParentTokenIntegrityLevel:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) string { return p.TokenIntegrityLevel })}
	case fields.PsTokenElevationType, fields.PsParentTokenElevationType:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) string { return p.TokenElevationType })}
	case fields.PsTokenIsElevated, fields.PsParentTokenIsElevated:
		return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPS(ps, func(p *pstypes.PS) bool { return p.IsTokenElevated })}
	}
	return processCollectionEvaluator(f)
}

// Slots of the memoized process iterators. The key of a result is the process
// it was computed for, so the process and its parent don't share one.
var (
	ancestorsSlot     = new(byte)
	ancestorNamesSlot = new(byte)
	handleNamesSlot   = new(byte)
	handleTypesSlot   = new(byte)
	moduleNamesSlot   = new(byte)
)

// ancestors walks up the process tree once per event, whichever of the
// ancestor fields asks for it.
func ancestors(ctx *EvalCtx, ps *pstypes.PS) []*pstypes.PS {
	return memoized(ctx, ancestorsSlot, ps, func() []*pstypes.PS {
		ancestors := make([]*pstypes.PS, 0)
		pstypes.Walk(func(proc *pstypes.PS) {
			if proc != nil {
				ancestors = append(ancestors, proc)
			}
		}, ps)
		return ancestors
	})
}

// ancestorNames returns the names of the ancestors in the order of the walk.
func ancestorNames(ctx *EvalCtx, ps *pstypes.PS) []string {
	return memoized(ctx, ancestorNamesSlot, ps, func() []string {
		names := make([]string, 0)
		for _, a := range ancestors(ctx, ps) {
			names = append(names, a.Name)
		}
		return names
	})
}

func handleNames(ctx *EvalCtx, ps *pstypes.PS) []string {
	return memoized(ctx, handleNamesSlot, ps, func() []string {
		names := make([]string, len(ps.Handles))
		for i, handle := range ps.Handles {
			names[i] = handle.Name
		}
		return names
	})
}

func handleTypes(ctx *EvalCtx, ps *pstypes.PS) []string {
	return memoized(ctx, handleTypesSlot, ps, func() []string {
		types := make([]string, len(ps.Handles))
		for i, handle := range ps.Handles {
			types[i] = handle.Type
		}
		return types
	})
}

func moduleNames(ctx *EvalCtx, ps *pstypes.PS) []string {
	return memoized(ctx, moduleNamesSlot, ps, func() []string {
		mods := make([]string, 0, len(ps.Modules))
		for _, m := range ps.Modules {
			mods = append(mods, m.Name)
		}
		return mods
	})
}

// processCollectionEvaluator returns the evaluator of the fields that are
// collections of the process state: the ancestors, the handles and the modules.
// They are iterators whose results are computed once per event, since several
// fields, and several rules, read the same one.
func processCollectionEvaluator(f Field) Evaluator {
	b := evaluatorBase(f)
	self := func(e *event.Event) *pstypes.PS { return e.PS }
	switch f.Name {
	// the process of the event and its parent have the same fields for the handles
	case fields.PsHandleNames:
		return psList(f, self, handleNames)
	case fields.PsHandleTypes:
		return psList(f, self, handleTypes)
	case fields.PsModuleNames:
		return psList(f, self, moduleNames)
	case fields.PsParentHandles:
		return psList(f, getParentPs, handleNames)
	case fields.PsParentHandleTypes:
		return psList(f, getParentPs, handleTypes)

	case fields.PsAncestors:
		return &FieldEvaluator[[]*pstypes.PS]{EvaluatorBase: b, Get: func(ctx *EvalCtx) ([]*pstypes.PS, bool) {
			if ctx.Evt.PS == nil {
				return nil, false
			}
			return ancestors(ctx, ctx.Evt.PS), true
		}}
	case fields.PsAncestor:
		// ps.ancestor[n] is the name of the ancestor at the level, and ps.ancestor
		// is the names of all of them
		return &AnyEvaluator{EvaluatorBase: b, Get: func(ctx *EvalCtx) (any, bool) {
			ps := ctx.Evt.PS
			if ps == nil {
				return nil, false
			}
			n := -1
			if f.Arg != "" {
				var err error
				n, err = f.IntArg()
				if err != nil {
					return nil, false
				}
			}
			names := ancestorNames(ctx, ps)
			if n < 0 {
				return names, true
			}
			if n < len(names) {
				return names[n], true
			}
			return "", true
		}}

	case fields.PsModules:
		return &FieldEvaluator[[]pstypes.Module]{EvaluatorBase: b, Get: optional(func(e *event.Event) ([]pstypes.Module, bool) {
			if e.PS == nil {
				return nil, false
			}
			return e.PS.Modules, true
		})}
	case fields.PsThreads:
		return &FieldEvaluator[map[uint32]pstypes.Thread]{EvaluatorBase: b, Get: optional(func(e *event.Event) (map[uint32]pstypes.Thread, bool) {
			if e.PS == nil {
				return nil, false
			}
			return e.PS.Threads, true
		})}
	case fields.PsMmaps:
		return &FieldEvaluator[[]pstypes.Mmap]{EvaluatorBase: b, Get: optional(func(e *event.Event) ([]pstypes.Mmap, bool) {
			if e.PS == nil {
				return nil, false
			}
			return e.PS.Mmaps, true
		})}

	// the access to a process is reported by the events that open one
	case fields.PsAccessMask:
		return &StringEvaluator{EvaluatorBase: b, Get: optional(func(e *event.Event) (string, bool) {
			if e.Type != event.OpenProcess {
				return "", false
			}
			return param(e, params.DesiredAccess, event.Params.GetStringByName), true
		})}
	case fields.PsAccessMaskNames:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: optional(func(e *event.Event) ([]string, bool) {
			if e.Type != event.OpenProcess {
				return nil, false
			}
			return e.GetFlagsAsSlice(params.DesiredAccess), true
		})}
	case fields.PsAccessStatus:
		return &StringEvaluator{EvaluatorBase: b, Get: optional(func(e *event.Event) (string, bool) {
			if e.Type != event.OpenProcess {
				return "", false
			}
			return e.GetParamAsString(params.NTStatus), true
		})}
	}
	return nil
}

// psList reads a list computed from the state of the process, once per event.
func psList(f Field, ps func(*event.Event) *pstypes.PS, get func(*EvalCtx, *pstypes.PS) []string) Evaluator {
	return &StringSliceEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) ([]string, bool) {
		p := ps(ctx.Evt)
		if p == nil {
			return nil, false
		}
		return get(ctx, p), true
	}}
}
