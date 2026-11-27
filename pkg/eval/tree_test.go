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
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// evalProgram evaluates the program on a fresh context.
func evalProgram(p *Program, evt *event.Event) (bool, *EvalCtx) {
	ctx := AcquireEvalCtx()
	return p.Eval(evt, ctx), ctx
}

func treeTestEvent() *event.Event {
	return &event.Event{
		Seq: 7, PID: 1023, Tid: 2048, CPU: 3, Host: "kitty",
		Timestamp: time.Date(2026, time.November, 24, 11, 31, 5, 0, time.UTC),
	}
}

// TestTreeFollowsThreeStateLogic pins down the corners of the evaluation: an
// expression that is undefined (an operator the type doesn't support) isn't the
// same as false, since negating it leaves it undefined, and it is cast to false
// only if the other operand is a bool.
func TestTreeFollowsThreeStateLogic(t *testing.T) {
	// evt.pid is an integer, so contains is undefined for it
	tests := []struct {
		expr     string
		expected bool
	}{
		{`evt.pid contains 1`, false},
		{`not (evt.pid contains 1)`, false},
		{`evt.pid contains 1 and evt.name = ''`, false},
		{`evt.pid contains 1 or evt.name = ''`, true},
		{`evt.pid contains 1 and evt.pid contains 1`, false},
		{`evt.pid contains 1 or evt.pid contains 1`, false},
		{`evt.pid contains 1 or true`, true},
		{`evt.pid contains 1 and true`, false},
		{`true and evt.pid contains 1`, false},
		{`false or evt.pid contains 1`, false},
		{`not (evt.pid contains 1 or true)`, false},
		{`not (evt.pid contains 1 and true)`, true},
		{`not (evt.pid = 1023)`, false},
		{`not (evt.pid = 1 or evt.tid = 2048)`, false},
		{`(evt.pid = 1023)`, true},
		{`evt.pid = 1023 and (evt.tid = 2048 or evt.cpu = 9)`, true},
		{`evt.pid = 1 or evt.tid = 2048 and evt.cpu = 3`, true},
		{`evt.name = 5`, false},
		{`evt.pid = 'x'`, false},
		{`true`, true},
		{`false`, false},
		{`not true`, false},
	}
	evt := treeTestEvent()
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			p, err := NewProgram("t", tt.expr)
			require.NoError(t, err)
			got, _ := evalProgram(p, evt)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestTreeExtractsFieldsOnlyWhenReached(t *testing.T) {
	evt := treeTestEvent()
	p, err := NewProgram("t", `evt.pid = 1 and evt.name = 'x' and evt.host = 'kitty'`)
	require.NoError(t, err)

	ok, ctx := evalProgram(p, evt)
	assert.False(t, ok)
	assert.Contains(t, ctx.Values, "evt.pid")
	assert.NotContains(t, ctx.Values, "evt.name", "the field of the operand that isn't reached was extracted")
	assert.NotContains(t, ctx.Values, "evt.host")

	p, err = NewProgram("t", `evt.pid = 1023 or evt.name = 'x'`)
	require.NoError(t, err)
	ok, ctx = evalProgram(p, evt)
	assert.True(t, ok)
	assert.NotContains(t, ctx.Values, "evt.name")

	// a field shared by the operands is extracted once and reused
	p, err = NewProgram("t", `evt.pid = 1023 and evt.pid > 1 and evt.pid < 2000`)
	require.NoError(t, err)
	ok, _ = evalProgram(p, evt)
	assert.True(t, ok)
}

func TestExtractLinkAlwaysExtractsTheLinkFields(t *testing.T) {
	evt := treeTestEvent()
	p, err := NewProgram("t", `sequence
	|evt.name = 'a' and evt.pid = 1| by evt.tid
	|evt.name = 'b'| by evt.tid
	`)
	require.NoError(t, err)
	require.True(t, p.IsSequenceExpr())
	seq := p.GetExpr().(*ast.SequenceExpr)

	// the first operand of the step is false, so the tree never gets to the
	// link field, and the sequence evaluator has to ask for it
	ctx := AcquireEvalCtx()
	assert.False(t, p.EvalExpr(seq.Steps[0].Expr, evt, ctx))
	assert.NotContains(t, ctx.Values, "evt.tid")

	p.ExtractLink(seq.Steps[0].By, evt, ctx)
	assert.Equal(t, uint32(2048), ctx.Values["evt.tid"])
	assert.Equal(t, uint32(2048), MakeSequenceLinkID(ctx, seq.Steps[0].By))
}

// treeGen generates random boolean expressions over the fields that exist on
// every platform. The operators and the operand types are mixed on purpose,
// so the expressions are undefined or constant often enough to exercise the
// corner cases of the three-state logic, not only the happy path.
type treeGen struct{ r *rand.Rand }

var (
	genStrFields = []string{"evt.name", "evt.category", "evt.host", "evt.time", "evt.date", "evt.date.tz", "evt.date.weekday", "evt.desc"}
	genIntFields = []string{"evt.pid", "evt.tid", "evt.cpu", "evt.seq", "evt.nparams", "evt.time.h", "evt.date.m", "evt.date.y", "evt.time.ns"}
	// genUndefFields have the operand type for which the parser accepts the
	// string operators, so the operator is undefined for the value at runtime
	genUndefFields = []string{"evt.pid", "evt.tid"}
	genStrings     = []string{"kitty", "", "KITTY", "Tuesday", "2026-11-24", "11:31:05", "UTC", "kit", "tty", "*itt*", "x"}
	genStrOps      = []string{"=", "!=", "~=", "contains", "icontains", "startswith", "istartswith", "endswith", "iendswith", "matches", "imatches"}
	genIntOps      = []string{"=", "!=", "<", "<=", ">", ">="}
)

func (g treeGen) pick(s []string) string { return s[g.r.Intn(len(s))] }

func (g treeGen) literalList() string {
	n := 1 + g.r.Intn(3)
	var b strings.Builder
	b.WriteByte('(')
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "'%s'", g.pick(genStrings))
	}
	b.WriteByte(')')
	return b.String()
}

func (g treeGen) leaf() string {
	switch g.r.Intn(9) {
	case 0:
		return g.pick([]string{"true", "false"})
	case 1, 2, 3:
		return fmt.Sprintf("%s %s '%s'", g.pick(genStrFields), g.pick(genStrOps), g.pick(genStrings))
	case 4:
		return fmt.Sprintf("%s in %s", g.pick(genStrFields), g.literalList())
	case 5, 6:
		return fmt.Sprintf("%s %s %d", g.pick(genIntFields), g.pick(genIntOps), []int{0, 1, 3, 7, 11, 1023, 2048, 2026}[g.r.Intn(8)])
	case 7:
		// the operator isn't defined for the operand type
		return fmt.Sprintf("%s %s %d", g.pick(genUndefFields), g.pick(genStrOps[3:]), g.r.Intn(5))
	default:
		return fmt.Sprintf("%s %s %s", g.pick(genIntFields), g.pick(genIntOps), g.pick(genIntFields))
	}
}

func (g treeGen) expr(depth int) string {
	if depth == 0 || g.r.Intn(4) == 0 {
		return g.leaf()
	}
	switch g.r.Intn(5) {
	case 0:
		return "not " + g.paren(depth-1)
	case 1:
		return g.paren(depth - 1)
	case 2:
		return fmt.Sprintf("%s or %s", g.expr(depth-1), g.expr(depth-1))
	default:
		return fmt.Sprintf("%s and %s", g.expr(depth-1), g.expr(depth-1))
	}
}

func (g treeGen) paren(depth int) string { return "(" + g.expr(depth) + ")" }

func (g treeGen) event() *event.Event {
	ts := time.Date(2020+g.r.Intn(10), time.Month(1+g.r.Intn(12)), 1+g.r.Intn(28), g.r.Intn(24), g.r.Intn(60), g.r.Intn(60), g.r.Intn(1000), time.UTC)
	return &event.Event{
		Seq: uint64(g.r.Intn(12)), PID: []uint32{0, 1, 1023, 2048}[g.r.Intn(4)], Tid: []uint32{0, 3, 2048}[g.r.Intn(3)],
		CPU: uint8(g.r.Intn(12)), Host: g.pick(genStrings), Timestamp: ts,
	}
}

// TestTreeMatchesRecordedResults evaluates the random expressions on the random
// events, and compares the results with the recorded ones. The results were
// recorded from the evaluation of the AST that the tree has replaced, so any
// change in how the expressions are evaluated has to be explained.
func TestTreeMatchesRecordedResults(t *testing.T) {
	data, err := os.ReadFile("testdata/tree.golden")
	require.NoError(t, err)

	var checked int
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var (
			seed int64
			bits string
		)
		_, err := fmt.Sscanf(line, "%d %s", &seed, &bits)
		require.NoError(t, err)

		g := treeGen{r: rand.New(rand.NewSource(seed))}
		expr := g.expr(1 + g.r.Intn(4))
		p, err := NewProgram("golden", expr)
		require.NoError(t, err, "seed %d: %s", seed, expr)

		for i := 0; i < len(bits); i++ {
			evt := g.event()
			got, _ := evalProgram(p, evt)
			if want := bits[i] == '1'; got != want {
				t.Fatalf("seed %d: %q on %+v: recorded %v, got %v", seed, expr, evt, want, got)
			}
		}
		checked++
	}
	assert.Equal(t, 1500, checked)
}
