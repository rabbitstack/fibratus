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

package rules

import (
	"sync"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/eval"
	"github.com/rabbitstack/fibratus/pkg/event"
)

// StepFunc is a pre-compiled sequence per-step callback. It
// receives an event and advances the lookup ladder if the
// event matches.
type SequenceStepFunc func(*event.Event, *eval.ValuerCache) bool

type SequenceStep struct {
}

// SequenceChain carries the accumulated events for one in-progress
// sequence match keyed by a link. It moves through the lookups
// ladder stage by stage until all nodes are satisfied.
type SequenceChain struct {
	events []*event.Event
}

// Advance returns a new chain with event appended at the next stage slot.
func (c *SequenceChain) Advance(e *event.Event) *SequenceChain {
	next := make([]*event.Event, len(c.events)+1)
	copy(next, c.events)
	next[len(c.events)] = e
	return &SequenceChain{events: next}
}

// Sequence is produced at compile time from a sequence expression.
// It holds one SequenceStepFunc per SequenceStep registered in reverse
// order.
// All mutable state, such as lookups is owned here and driven by the
// engine on event handling.
type SequenceEvaluator struct {
	// steps holds one compiled callback per sequence step.
	// Stored and called in reverse order so a single event
	// cannot advance through multiple stages in one call.
	steps []SequenceStepFunc

	// lookups is the join-value ladder. lookups[i] maps a join
	// key to the single confirmed event chain that matched stage
	// at index i.
	lookups []map[any]*SequenceChain
	mu      sync.Mutex

	evaluator *eval.Evaluator

	depth  int
	events []*event.Event
}

func MakeSequenceEvaluator(evaluator *eval.Evaluator) RuleEvaluator {
	depth := evaluator.GetDepth()

	seq := &SequenceEvaluator{
		depth:     depth,
		evaluator: evaluator,
		steps:     make([]SequenceStepFunc, depth),
		lookups:   make([]map[any]*SequenceChain, depth),
	}

	for i := range seq.lookups {
		seq.lookups[i] = make(map[any]*SequenceChain)
	}

	expr := evaluator.GetExpr().(*ast.SequenceExpr)

	// compile in reverse so one event can't advance multiple stages in one pass
	for pos := depth - 1; pos >= 0; pos-- {
		pos := pos // capture
		step := &expr.Steps[pos]

		evaluate := func(event *event.Event, valuer *eval.ValuerCache) bool {
			return seq.evaluator.EvalExpr(step.Expr, event, valuer)
		}
		link := func(valuer *eval.ValuerCache) any {
			by := seq.evaluator.GetLink(pos)
			if by == nil {
				return struct{}{} // unconstrained means all events share one bucket
			}
			return eval.MakeSequenceLinkID(valuer, by)
		}

		switch {
		case pos == 0:
			// first stage seeds the ladder
			seq.steps[pos] = func(e *event.Event, valuer *eval.ValuerCache) bool {
				if !evaluate(e, valuer) {
					return false
				}
				// lookups[0] is unused. The first steps writes into lookups[1].
				seq.lookups[1][link(valuer)] = &SequenceChain{events: []*event.Event{e}}
				return true
			}
		case pos < depth-1:
			// middle step advances the ladder. The new chain carries all prior
			// events plus the matching event originated in this stage.
			next := pos + 1
			seq.steps[pos] = func(e *event.Event, valuer *eval.ValuerCache) bool {
				if len(seq.lookups[pos]) == 0 {
					return false
				}

				if !evaluate(e, valuer) {
					return false
				}

				l := link(valuer)
				chain, ok := seq.lookups[pos][l]
				if !ok {
					return false
				}
				delete(seq.lookups[pos], l)
				// overwrite any existing chain in the next stage
				// a more recent match supersedes a stale pending chain
				seq.lookups[next][l] = chain.Advance(e)
				return true
			}
		default:
			// final stage emits the match
			seq.steps[pos] = func(e *event.Event, valuer *eval.ValuerCache) bool {
				if len(seq.lookups[pos]) == 0 {
					return false
				}

				if !evaluate(e, valuer) {
					return false
				}

				l := link(valuer)
				chain, ok := seq.lookups[pos][l]
				if !ok {
					return false
				}
				delete(seq.lookups[pos], l)
				// the chain is completed here so we can accumulate
				// all events that participated in the sequence match
				seq.events = chain.Advance(e).events
				return true
			}
		}
	}

	return seq
}

// expire expires sequence chains when a TerminateProcess event arrives
// for a process involved in the chain.
//
// Expiry rules (applied per chain across all checkpoint stages):
//
//  1. If the final stage slot holds a CreateProcess event and its spawned
//     pid matches TerminateProcess.pid → expire the entire chain.
//  2. Otherwise, walk every event in the chain:
//     - CreateThread with a remote pid (evt.PID != evt.Params.MustGetPid()):
//     expire if the remote pid matches TerminateProcess.pid.
//     - All other events: expire if evt.PID matches TerminateProcess.pid.
//
// When a chain is expired it is deleted from every checkpoint stage that
// holds it (identified by join key). The walk is O(chains × stages) but
// only executes on TerminateProcess events.
func (s *SequenceEvaluator) expire(evt *event.Event) bool {
	if !evt.IsTerminateProcess() {
		return false
	}
	pid := evt.Params.MustGetPid()
	numStages := len(s.steps)

	canExpire := func(chain *SequenceChain) bool {
		lastIdx := len(chain.events) - 1

		// Case 1: final stage holds a CreateProcess event — expire if
		// the spawned pid (stored in params) matches the terminating pid.
		if lastIdx == numStages-1 && chain.events[lastIdx].IsCreateProcess() {
			return chain.events[lastIdx].Params.MustGetPid() == pid
		}

		// Case 2: no CreateProcess in the final slot — walk all events
		// in the chain and expire if any event's relevant pid matches.
		for _, evt := range chain.events {
			if evt.Type == event.CreateThread {
				// Remote thread creation: the thread lives in a
				// different process, so match on the remote pid
				// instead of evt.PID.
				if remotePID, err := evt.Params.GetPid(); err == nil && evt.PID != remotePID {
					if remotePID == pid {
						return true
					}
					continue
				}
			}
			// All other events (including local CreateThread): match
			// on owning pid.
			if evt.PID == pid {
				return true
			}
		}
		return false
	}

	// Scan every lookups stage for chains to expire. An in-progress
	// chain's join key is present in exactly one stage at any time, so
	// all stages must be checked to catch chains at any point in the ladder.
	for stageIdx := 1; stageIdx < len(s.lookups); stageIdx++ {
		for link, chain := range s.lookups[stageIdx] {
			if !canExpire(chain) {
				continue
			}
			for _, stage := range s.lookups {
				delete(stage, link)
			}
		}
	}
	return false
}

func (s *SequenceEvaluator) evaluate(event *event.Event, valuer *eval.ValuerCache, stepIndex int) bool {
	// if !r.rule.eval.IsEvaluable(event) {
	// 	return false
	// }
	return false
}

func (s *SequenceEvaluator) Evaluate(event *event.Event, valuer *eval.ValuerCache) ([]*event.Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.expire(event) {

	}

	for i := 0; i < len(s.steps); i++ {
		s.steps[i](event, valuer)
	}

	if s.events != nil {
		evts := s.events
		s.events = nil // reset for next match
		return evts, true
	}

	return nil, false
}

// func (e *SequenceStep) init() {
// 	e.types = make([]event.Type, 0)
// 	e.BoundFields = make([]*BoundFieldLiteral, 0)
// }

// func (e *SequenceStep) walk() {
// 	stringFields := make(map[fields.Field][]string)
// 	walk := func(n Node) {
// 		if expr, ok := n.(*BinaryExpr); ok {
// 			switch lhs := expr.LHS.(type) {
// 			case *BoundFieldLiteral:
// 				e.BoundFields = append(e.BoundFields, lhs)
// 			case *FieldLiteral:
// 				field := fields.Field(lhs.Value)
// 				switch v := expr.RHS.(type) {
// 				case *StringLiteral:
// 					stringFields[field] = append(stringFields[field], v.Value)
// 				case *ListLiteral:
// 					stringFields[field] = append(stringFields[field], v.Values...)
// 				}
// 			}

// 			switch rhs := expr.RHS.(type) {
// 			case *BoundFieldLiteral:
// 				e.BoundFields = append(e.BoundFields, rhs)
// 			case *FieldLiteral:
// 				field := fields.Field(rhs.Value)
// 				switch v := expr.LHS.(type) {
// 				case *StringLiteral:
// 					stringFields[field] = append(stringFields[field], v.Value)
// 				case *ListLiteral:
// 					stringFields[field] = append(stringFields[field], v.Values...)
// 				}
// 			}
// 		}

// 		if expr, ok := n.(*Function); ok {
// 			for _, arg := range expr.Args {
// 				switch v := arg.(type) {
// 				case *FieldLiteral:
// 					field := fields.Field(v.Value)
// 					stringFields[field] = append(stringFields[field], v.Value)
// 				case *BoundFieldLiteral:
// 					e.BoundFields = append(e.BoundFields, v)
// 				}
// 			}
// 		}
// 	}

// 	WalkFunc(e.Expr, walk)

// 	uniqCats := make(map[event.Category]bool)

// 	// initialize event type/category buckets for every such field
// 	for name, values := range stringFields {
// 		for _, v := range values {
// 			switch name {
// 			case fields.EvtName:
// 				for _, typ := range event.NameToTypes(v) {
// 					if typ == event.UnknownType {
// 						continue
// 					}
// 					e.types = append(e.types, typ)
// 					uniqCats[event.TypeToEventInfo(typ).Category] = true
// 				}
// 			case fields.EvtCategory:
// 				e.bitsets.SetCategoryBit(event.Category(v))
// 			}
// 		}
// 	}

// 	for _, t := range e.types {
// 		switch len(uniqCats) {
// 		case 0:
// 			continue
// 		case 1:
// 			// happy path can use a single bitmask for all
// 			// event types pertaining to the same category
// 			e.bitsets.SetBit(event.TypeBitSet, t)
// 		default:
// 			// use map-backed bitmask for event identifiers
// 			e.bitsets.SetBit(event.BitmaskBitSet, t)
// 		}
// 	}
// }
