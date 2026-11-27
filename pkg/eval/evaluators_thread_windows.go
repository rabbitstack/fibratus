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
	"path/filepath"

	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
)

// Slots of the memoized results of the callstack iterators.
var (
	finalUserFrameSlot     = new(byte)
	finalKernelFrameSlot   = new(byte)
	finalUserSignatureSlot = new(byte)
)

// finalUserFrame returns the final user frame of the callstack. The frame is
// found once per event, though several fields describe it.
func finalUserFrame(ctx *EvalCtx) *callstack.Frame {
	e := ctx.Evt
	return memoized(ctx, finalUserFrameSlot, e, func() *callstack.Frame { return e.Callstack.FinalUserFrame() })
}

// finalKernelFrame returns the final kernel frame of the callstack.
func finalKernelFrame(ctx *EvalCtx) *callstack.Frame {
	e := ctx.Evt
	return memoized(ctx, finalKernelFrameSlot, e, func() *callstack.Frame { return e.Callstack.FinalKernelFrame() })
}

// finalUserSignature resolves the signature of the module that backs the final
// user frame. It reports false if there is no frame, no module or no signature,
// and when the process state is missing, which reads as no value.
func finalUserSignature(ctx *EvalCtx) (*signature.Signature, bool) {
	type result struct {
		sign *signature.Signature
		ok   bool
	}
	r := memoized(ctx, finalUserSignatureSlot, ctx.Evt, func() result {
		frame := finalUserFrame(ctx)
		if frame == nil || frame.ModuleAddress.IsZero() {
			return result{}
		}
		ps := ctx.Evt.PS
		if ps == nil {
			return result{}
		}
		mod := ps.FindModuleByVa(frame.Addr)
		if mod == nil {
			return result{}
		}
		sign := ctx.Resolvers.Signature.Of(ctx, signature.MakeKey(mod.Name, mod.Size, mod.Checksum, mod.TimedateStamp))
		return result{sign: sign, ok: sign != nil}
	})
	return r.sign, r.ok
}

// framePID returns the process that owns the callstack frames.
func framePID(e *event.Event) uint32 {
	if !e.Callstack.IsEmpty() && e.Callstack.FrameAt(0).PID != 0 {
		return e.Callstack.FrameAt(0).PID
	}
	return e.PID
}

// threadEvaluator returns the thread.* evaluator of the field, the callstack
// ones included, or nil if the field isn't one of them. The callstack signature
// fields resolve the signature of the module of the final user frame through
// the signature resolver.
func threadEvaluator(f Field) Evaluator {
	b := evaluatorBase(f)
	switch f.Name {
	case fields.ThreadBasePrio:
		return &Uint8Evaluator{EvaluatorBase: b, Get: fromParam(params.BasePrio, event.Params.GetUint8ByName)}
	case fields.ThreadIOPrio:
		return &Uint8Evaluator{EvaluatorBase: b, Get: fromParam(params.IOPrio, event.Params.GetUint8ByName)}
	case fields.ThreadPagePrio:
		return &Uint8Evaluator{EvaluatorBase: b, Get: fromParam(params.PagePrio, event.Params.GetUint8ByName)}
	case fields.ThreadKstackBase:
		return stringParam(f, params.KstackBase)
	case fields.ThreadKstackLimit:
		return stringParam(f, params.KstackLimit)
	case fields.ThreadUstackBase:
		return stringParam(f, params.UstackBase)
	case fields.ThreadUstackLimit:
		return stringParam(f, params.UstackLimit)
	case fields.ThreadEntrypoint, fields.ThreadStartAddress:
		return stringParam(f, params.StartAddress)
	case fields.ThreadTEB:
		return stringParam(f, params.TEB)
	case fields.ThreadPID:
		return uint32Param(f, params.ProcessID)

	// the fields that exist for some event types only
	case fields.ThreadAccessMask:
		return eventOnly(f, event.OpenThread, func(e *event.Event) string {
			return param(e, params.DesiredAccess, event.Params.GetStringByName)
		})
	case fields.ThreadAccessStatus:
		return eventOnly(f, event.OpenThread, func(e *event.Event) string { return e.GetParamAsString(params.NTStatus) })
	case fields.ThreadStartAddressSymbol:
		return eventOnly(f, event.CreateThread, func(e *event.Event) string {
			return e.GetParamAsString(params.StartAddressSymbol)
		})
	case fields.ThreadStartAddressModule:
		return eventOnly(f, event.CreateThread, func(e *event.Event) string {
			return e.GetParamAsString(params.StartAddressModule)
		})
	case fields.ThreadAccessMaskNames:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: optional(func(e *event.Event) ([]string, bool) {
			if e.Type != event.OpenThread {
				return nil, false
			}
			return e.GetFlagsAsSlice(params.DesiredAccess), true
		})}
	}
	return callstackEvaluator(f)
}

// eventOnly reads a field that exists for the events of a single type only.
func eventOnly(f Field, typ event.Type, get func(*event.Event) string) Evaluator {
	return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: optional(func(e *event.Event) (string, bool) {
		if e.Type != typ {
			return "", false
		}
		return get(e), true
	})}
}

// callstackEvaluator returns the evaluator of the callstack fields, or nil if
// the field isn't one of them.
func callstackEvaluator(f Field) Evaluator {
	b := evaluatorBase(f)
	switch f.Name {
	case fields.ThreadCallstackSummary:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string { return e.Callstack.Summary(callstack.UserSummary) })}
	case fields.ThreadCallstackKernelSummary:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string { return e.Callstack.Summary(callstack.KernelSummary) })}
	case fields.ThreadCallstackDetail:
		return &StringEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) string { return e.Callstack.String() })}
	case fields.ThreadCallstackAddresses:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) []string { return e.Callstack.Addresses() })}
	case fields.ThreadCallstackIsUnbacked:
		return &BoolEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) bool { return e.Callstack.ContainsUnbacked() })}
	case fields.ThreadCallstack:
		return &FieldEvaluator[callstack.Callstack]{EvaluatorBase: b, Get: always(func(e *event.Event) callstack.Callstack { return e.Callstack })}
	case fields.ThreadCallstackAllocationSizes:
		return &FieldEvaluator[[]uint64]{EvaluatorBase: b, Get: always(func(e *event.Event) []uint64 {
			return e.Callstack.AllocationSizes(framePID(e))
		})}
	case fields.ThreadCallstackProtections:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) []string {
			return e.Callstack.Protections(framePID(e))
		})}
	case fields.ThreadCallstackCallsiteLeadingAssembly:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) []string {
			return e.Callstack.CallsiteInsns(framePID(e), true)
		})}
	case fields.ThreadCallstackCallsiteTrailingAssembly:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: always(func(e *event.Event) []string {
			return e.Callstack.CallsiteInsns(framePID(e), false)
		})}

	// the modules and the symbols are all the frames, or the one at the level
	// given as the argument, so the type depends on how the field is written
	case fields.ThreadCallstackModules:
		return callstackFrames(f, func(e *event.Event) []string { return e.Callstack.Modules() },
			func(fr callstack.Frame) string { return fr.Module })
	case fields.ThreadCallstackSymbols:
		return callstackFrames(f, func(e *event.Event) []string { return e.Callstack.Symbols() },
			func(fr callstack.Frame) string { return fr.Symbol })

	// the final frames are found once per event for all the fields that describe them
	case fields.ThreadCallstackFinalUserModuleName:
		return finalFrame(f, finalUserFrame, func(fr *callstack.Frame) string { return filepath.Base(fr.Module) })
	case fields.ThreadCallstackFinalUserModulePath:
		return finalFrame(f, finalUserFrame, func(fr *callstack.Frame) string { return fr.Module })
	case fields.ThreadCallstackFinalUserSymbolName:
		return finalFrame(f, finalUserFrame, func(fr *callstack.Frame) string { return fr.Symbol })
	case fields.ThreadCallstackFinalKernelModuleName:
		return finalFrame(f, finalKernelFrame, func(fr *callstack.Frame) string { return filepath.Base(fr.Module) })
	case fields.ThreadCallstackFinalKernelModulePath:
		return finalFrame(f, finalKernelFrame, func(fr *callstack.Frame) string { return fr.Module })
	case fields.ThreadCallstackFinalKernelSymbolName:
		return finalFrame(f, finalKernelFrame, func(fr *callstack.Frame) string { return fr.Symbol })

	case fields.ThreadCallstackFinalUserModuleSignatureExists:
		return finalSignatureVerdict(f, (*signature.Signature).Exists)
	case fields.ThreadCallstackFinalUserModuleSignatureTrusted:
		return finalSignatureVerdict(f, (*signature.Signature).IsTrusted)
	case fields.ThreadCallstackFinalUserModuleSignatureIssuer:
		return finalSignatureCert(f, func(s *signature.Signature) string { return s.Cert().Issuer })
	case fields.ThreadCallstackFinalUserModuleSignatureSubject:
		return finalSignatureCert(f, func(s *signature.Signature) string { return s.Cert().Subject })
	}
	return nil
}

// callstackFrames reads all the frames, or the one at the level given as the
// argument, e.g. thread.callstack.modules[2].
func callstackFrames(f Field, all func(*event.Event) []string, one func(callstack.Frame) string) Evaluator {
	return &AnyEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) (any, bool) {
		e := ctx.Evt
		if f.Arg == "" {
			return all(e), true
		}
		n, err := f.IntArg()
		if err != nil {
			return nil, false
		}
		if n > e.Callstack.Depth() {
			return "", true
		}
		return one(e.Callstack.FrameAt(n)), true
	}}
}

// finalFrame reads a property of the final frame. The field has no value if
// there is no such frame.
func finalFrame(f Field, frame func(*EvalCtx) *callstack.Frame, get func(*callstack.Frame) string) Evaluator {
	return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) (string, bool) {
		fr := frame(ctx)
		if fr == nil {
			return "", false
		}
		return get(fr), true
	}}
}

func finalSignatureVerdict(f Field, get func(*signature.Signature) bool) Evaluator {
	return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) (bool, bool) {
		sign, ok := finalUserSignature(ctx)
		if !ok {
			return false, false
		}
		return get(sign), true
	}}
}

func finalSignatureCert(f Field, get func(*signature.Signature) string) Evaluator {
	return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) (string, bool) {
		sign, ok := finalUserSignature(ctx)
		if !ok || !sign.HasCertificate() {
			return "", false
		}
		return get(sign), true
	}}
}
