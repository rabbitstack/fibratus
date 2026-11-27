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
)

// eventEvaluator returns the evaluator of the fields read from the event itself,
// or nil if the field isn't one of them. Each one returns the value with the Go
// type the field is declared with.
func eventEvaluator(f Field) Evaluator {
	switch f.Name {
	case fields.EvtArg:
		return evtArgEvaluator(f)

	case fields.EvtSeq:
		return &Uint64Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint64 { return e.Seq })}
	case fields.EvtPID:
		return &Uint32Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint32 { return e.PID })}
	case fields.EvtTID:
		return &Uint32Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint32 { return e.Tid })}
	case fields.EvtCPU:
		return &Uint8Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint8 { return e.CPU })}
	case fields.EvtName:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) string { return e.Name() })}
	case fields.EvtCategory:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) string { return e.Category().String() })}
	case fields.EvtDesc:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) string { return e.Description() })}
	case fields.EvtHost:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) string { return e.Host })}

	case fields.EvtTime:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) string { return e.Timestamp.Format(timeFmt) })}
	case fields.EvtTimeHour:
		return &Uint8Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint8 { return uint8(e.Timestamp.Hour()) })}
	case fields.EvtTimeMin:
		return &Uint8Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint8 { return uint8(e.Timestamp.Minute()) })}
	case fields.EvtTimeSec:
		return &Uint8Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint8 { return uint8(e.Timestamp.Second()) })}
	case fields.EvtTimeNs:
		return &Int64Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) int64 { return e.Timestamp.UnixNano() })}

	case fields.EvtDate:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) string { return e.Timestamp.Format(dateFmt) })}
	case fields.EvtDateDay:
		return &Uint8Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint8 { return uint8(e.Timestamp.Day()) })}
	case fields.EvtDateMonth:
		return &Uint8Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint8 { return uint8(e.Timestamp.Month()) })}
	case fields.EvtDateTz:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) string {
			tz, _ := e.Timestamp.Zone()
			return tz
		})}
	case fields.EvtDateYear:
		return &Uint32Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint32 { return uint32(e.Timestamp.Year()) })}
	case fields.EvtDateWeek:
		return &Uint8Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint8 {
			_, week := e.Timestamp.ISOWeek()
			return uint8(week)
		})}
	case fields.EvtDateWeekday:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) string { return e.Timestamp.Weekday().String() })}

	case fields.EvtNparams:
		return &Uint64Evaluator{EvaluatorBase: evaluatorBase(f), Get: always(func(e *event.Event) uint64 { return uint64(e.Params.Len()) })}
	}
	return nil
}

// evtArgEvaluator reads evt.arg[name], the event parameter of the name given
// as the argument. Depending on the type of the parameter, the value is a
// number of the matching width, a time or its formatted form.
func evtArgEvaluator(f Field) Evaluator {
	name := f.Arg
	return &AnyEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) (any, bool) {
		evt := ctx.Evt
		idx := evt.Params.Index(name)
		if !evt.Params.Has(idx) {
			return nil, false
		}
		switch evt.Params.Type(idx) {
		case params.Uint8:
			return evt.Params.GetUint8(idx), true
		case params.Uint16, params.Port:
			return evt.Params.GetUint16(idx), true
		case params.Uint32, params.PID, params.TID:
			return evt.Params.GetUint32(idx), true
		case params.Uint64:
			return evt.Params.GetUint64(idx), true
		case params.Time:
			return evt.Params.GetTime(idx), true
		default:
			return evt.Params.Format(idx), true
		}
	}}
}
