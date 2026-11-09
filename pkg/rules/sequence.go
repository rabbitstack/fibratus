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

package rules

import (
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/eval"
	"github.com/rabbitstack/fibratus/pkg/event"
	log "github.com/sirupsen/logrus"
)

// SequenceStepFunc is a pre-compiled sequence per-step callback. It
// receives an event and advances the lookup ladder if the event
// matches. It returns true if the event advanced the ladder.
type SequenceStepFunc func(*event.Event, *eval.ValuerCache) bool

// SequenceStep is the compiled sequence step. Besides the callback, it
// keeps the expression and the join/bound information of the step.
type SequenceStep struct {
	fn    SequenceStepFunc
	expr  ast.Expr
	by    *ast.SequenceLink
	bound []boundRef
}

// SequenceChain carries the accumulated events for one in-progress
// sequence match keyed by a link. It moves through the lookups
// ladder stage by stage until all steps are satisfied.
type SequenceChain struct {
	events []*event.Event

	// id uniquely identifies the chain. It is preserved when
	// the chain advances, so the deadline timer can find it
	id uint64

	// link is the join value the chain is stored under in the ladder
	link any

	// stage is the index of the step that consumes the chain next
	stage int

	// timer fires when the maxspan deadline elapses
	timer *time.Timer
}

// Advance returns a new chain with event appended at the next stage slot.
// The new chain inherits the identity, the join key and the deadline of the
// original chain.
func (c *SequenceChain) Advance(e *event.Event) *SequenceChain {
	next := make([]*event.Event, len(c.events)+1)
	copy(next, c.events)
	next[len(c.events)] = e
	return &SequenceChain{events: next, id: c.id, link: c.link, stage: c.stage, timer: c.timer}
}

// boundRef is the reference to the field of the event that was matched
// by a previous sequence step, e.g. $e1.ps.sid.
type boundRef struct {
	// value is the key the bound literal is looked up with in the valuer
	value string
	field eval.Field
	// stage is the index of the step that declares the alias
	stage int
}

// SequenceEvaluator evaluates the sequence rules. It is produced at compile
// time from the sequence expression, and holds one compiled SequenceStep for
// every step of the sequence. The ladder keeps a map for each stage, i.e.
// lookups[i] maps the join key to the chain waiting for the step i to match.
// A chain seeded by the first step is stored in lookups[1], and moves one
// stage up each time the step of the stage matches, until the last step
// completes the match. All mutable state is owned here.
//
// Steps that reference the events of the previous steps through bound fields
// (e.g. $e1.ps.sid) can't be joined by a single key. They scan the chains
// that wait in the stage, oldest first, and pick the first chain for which
// the bound condition holds.
//
// If the sequence has the maxspan, the chain is dropped when the deadline
// elapses, counted from the first event of the chain.
type SequenceEvaluator struct {
	mu sync.Mutex

	evaluator *eval.Evaluator

	// steps holds one compiled step per sequence step. They are stored
	// in the reverse order and called in that order, so a single event
	// cannot advance a chain through multiple stages in one call.
	steps   []SequenceStep
	maxSpan time.Duration
	lookups []map[any]*SequenceChain

	// live indexes the chains that wait in the ladder by their identifier
	live   map[uint64]*SequenceChain
	nextID uint64
	// unique indicates that chains can't be joined by a key, so
	// each chain is stored under its own identifier
	unique bool

	// events are the events of the match completed by the last step
	events []*event.Event
}

// MakeSequenceEvaluator creates the evaluator for the sequence rule.
func MakeSequenceEvaluator(evaluator *eval.Evaluator) (RuleEvaluator, error) {
	expr := evaluator.GetExpr().(*ast.SequenceExpr)
	depth := expr.Depth()

	seq := &SequenceEvaluator{
		evaluator: evaluator,
		steps:     make([]SequenceStep, depth),
		maxSpan:   expr.MaxSpan,
		lookups:   make([]map[any]*SequenceChain, depth),
		live:      make(map[uint64]*SequenceChain),
	}
	for i := range seq.lookups {
		seq.lookups[i] = make(map[any]*SequenceChain)
	}

	aliases := make(map[string]int)
	compiled := make([]SequenceStep, depth)
	for pos := range expr.Steps {
		step := &expr.Steps[pos]
		by := expr.By
		if by == nil {
			by = step.By
		}
		bound, err := boundRefs(step.Expr, aliases)
		if err != nil {
			return nil, fmt.Errorf("step %d: %w", pos+1, err)
		}
		compiled[pos] = SequenceStep{expr: step.Expr, by: by, bound: bound}
		if pos > 0 && by == nil && len(bound) > 0 {
			seq.unique = true
		}

		if step.BareVariable != "" {
			alias := normalizeAlias(step.BareVariable)
			if _, ok := aliases[alias]; ok {
				return nil, fmt.Errorf("step %d: duplicate alias $%s", pos+1, alias)
			}
			aliases[alias] = pos
		}
	}

	// compile in reverse so one event can't advance multiple stages in one pass
	for pos := depth - 1; pos >= 0; pos-- {
		pos := pos // capture
		step := compiled[pos]
		step.fn = func(e *event.Event, valuer *eval.ValuerCache) bool {
			evts := seq.advance(pos, e, valuer)
			if evts == nil {
				return false
			}
			seq.events = evts
			return true
		}
		seq.steps[depth-1-pos] = step
	}

	return seq, nil
}

// normalizeAlias strips the leading $ from the bound variable.
func normalizeAlias(alias string) string { return strings.TrimPrefix(alias, "$") }

// boundRefs collects the bound fields the step expression references. The
// aliases are the ones declared by the preceding steps.
func boundRefs(expr ast.Expr, aliases map[string]int) ([]boundRef, error) {
	var (
		refs []boundRef
		seen = make(map[string]struct{})
		err  error
	)
	ast.WalkFunc(expr, func(n ast.Node) {
		f, ok := n.(*ast.BoundFieldLiteral)
		if !ok || err != nil {
			return
		}
		if _, ok := seen[f.Value]; ok {
			return
		}
		seen[f.Value] = struct{}{}
		alias := normalizeAlias(f.BoundVar.Value)
		stage, ok := aliases[alias]
		if !ok {
			err = fmt.Errorf("bound field %s references an unknown or a later sequence alias $%s", f.Value, alias)
			return
		}
		refs = append(refs, boundRef{
			value: f.Value,
			field: eval.Field{Name: f.Field.Field, Value: f.Field.Value, Arg: f.Field.Arg},
			stage: stage,
		})
	})
	return refs, err
}

// Evaluate feeds the event to the sequence. It returns the events of all
// steps if the event completes the sequence.
func (s *SequenceEvaluator) Evaluate(e *event.Event, valuer *eval.ValuerCache) ([]*event.Event, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.expire(e)

	s.evaluator.Extract(e, valuer)

	// the steps are stored from the last to the first one
	for _, step := range s.steps {
		step.fn(e, valuer)
	}

	if s.events != nil {
		evts := s.events
		s.events = nil // reset for next match
		return evts, true
	}

	return nil, false
}

// advance tries to advance the ladder with the event on the given step.
// It returns the events of the matched sequence if the last step completes it.
func (s *SequenceEvaluator) advance(pos int, e *event.Event, valuer *eval.ValuerCache) []*event.Event {
	step := &s.steps[len(s.steps)-1-pos]

	if pos == 0 {
		if !s.evaluator.EvalExpr(step.expr, e, valuer) {
			return nil
		}
		c := &SequenceChain{id: s.newID(), stage: 1, events: []*event.Event{e}}
		switch {
		case step.by != nil:
			c.link = eval.MakeSequenceLinkID(valuer, step.by)
		case s.unique:
			c.link = c.id
		default:
			// all events share one chain
			c.link = struct{}{}
		}
		if s.maxSpan > 0 {
			id := c.id
			c.timer = time.AfterFunc(s.maxSpan, func() { s.expireChain(id) })
		}
		s.live[c.id] = c
		s.put(1, c)
		return nil
	}

	stage := s.lookups[pos]
	if len(stage) == 0 {
		return nil
	}

	c := s.match(step, stage, e, valuer)
	if c == nil {
		return nil
	}

	delete(stage, c.link)
	next := c.Advance(e)
	if pos == len(s.steps)-1 {
		// the chain is completed here, so all events that
		// participated in the match are returned
		s.retire(next)
		return next.events
	}
	next.stage = pos + 1
	s.live[next.id] = next
	s.put(next.stage, next)

	return nil
}

// match finds the chain waiting in the stage that the event advances.
func (s *SequenceEvaluator) match(step *SequenceStep, stage map[any]*SequenceChain, e *event.Event, valuer *eval.ValuerCache) *SequenceChain {
	// a step without bound fields only needs to be evaluated once
	if len(step.bound) == 0 && !s.evaluator.EvalExpr(step.expr, e, valuer) {
		return nil
	}

	var candidates []*SequenceChain
	if step.by != nil {
		if c, ok := stage[eval.MakeSequenceLinkID(valuer, step.by)]; ok {
			candidates = append(candidates, c)
		}
	} else {
		for _, c := range stage {
			candidates = append(candidates, c)
		}
		slices.SortFunc(candidates, func(a, b *SequenceChain) int {
			switch {
			case a.id < b.id:
				return -1
			case a.id > b.id:
				return 1
			}
			return 0
		})
	}

	for _, c := range candidates {
		// the event arrived after the deadline, but the timer didn't fire yet
		if s.maxSpan > 0 && e.Timestamp.Sub(c.events[0].Timestamp) > s.maxSpan {
			s.drop(c)
			continue
		}
		if len(step.bound) == 0 || s.evalBound(step, c, e, valuer) {
			return c
		}
	}
	return nil
}

// evalBound evaluates the step expression with the bound fields
// resolved from the events the chain has accumulated.
func (s *SequenceEvaluator) evalBound(step *SequenceStep, c *SequenceChain, e *event.Event, valuer *eval.ValuerCache) bool {
	for _, ref := range step.bound {
		if ref.stage >= len(c.events) {
			continue
		}
		valuer.Valuer[ref.value] = ref.field.Extract(c.events[ref.stage])
	}
	defer func() {
		for _, ref := range step.bound {
			delete(valuer.Valuer, ref.value)
		}
	}()
	return s.evaluator.EvalExpr(step.expr, e, valuer)
}

func (s *SequenceEvaluator) newID() uint64 {
	s.nextID++
	return s.nextID
}

// put stores the chain in the stage. A more recent chain
// supersedes the stale chain with the same join key.
func (s *SequenceEvaluator) put(stage int, c *SequenceChain) {
	if prev, ok := s.lookups[stage][c.link]; ok && prev != c {
		s.drop(prev)
	}
	s.lookups[stage][c.link] = c
}

// retire forgets about the chain and cancels its deadline.
func (s *SequenceEvaluator) retire(c *SequenceChain) {
	delete(s.live, c.id)
	if c.timer != nil {
		c.timer.Stop()
	}
}

// drop removes the chain from whichever stage it currently occupies.
func (s *SequenceEvaluator) drop(c *SequenceChain) {
	if s.live[c.id] != c {
		return
	}
	s.retire(c)
	if s.lookups[c.stage][c.link] == c {
		delete(s.lookups[c.stage], c.link)
	}
}

// expireChain is called when the maxspan deadline of the chain elapses.
func (s *SequenceEvaluator) expireChain(id uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.live[id]
	if !ok {
		return
	}
	log.Debugf("sequence maxspan [%s] elapsed, dropping the chain of %d event(s)", s.maxSpan, len(c.events))
	s.drop(c)
}

// expire drops the chains that contain the events of the process terminated by the event.
func (s *SequenceEvaluator) expire(evt *event.Event) {
	if !evt.IsTerminateProcess() {
		return
	}
	pid, err := evt.Params.GetPid()
	if err != nil {
		return
	}

	canExpire := func(e *event.Event, pid uint32) bool {
		// the chain can be dropped only if the remote process terminates
		if e.IsCreateRemoteThread() {
			return e.Params.MustGetPid() == pid
		}
		// final stage holds a CreateProcess event. Only expire
		// if the spawned pid matches the terminating pid
		//TODO:

		// Everything else
		return e.PID == pid
	}

	for _, stage := range s.lookups {
		for _, chain := range stage {
			if slices.ContainsFunc(chain.events,
				func(evt *event.Event) bool { return canExpire(evt, pid) }) {
				s.drop(chain)
			}
		}
	}
}

// Len returns the number of in-progress chains.
func (s *SequenceEvaluator) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, stage := range s.lookups {
		n += len(stage)
	}
	return n
}
