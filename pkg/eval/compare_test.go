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
	"math"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var comparisonOps = []lexer.Token{
	lexer.Eq, lexer.IEq, lexer.Neq, lexer.Lt, lexer.Lte, lexer.Gt, lexer.Gte,
	lexer.In, lexer.IIn, lexer.Contains, lexer.IContains, lexer.Startswith,
	lexer.IStartswith, lexer.Endswith, lexer.IEndswith, lexer.Matches,
	lexer.IMatches, lexer.Fuzzy, lexer.IFuzzy, lexer.Fuzzynorm, lexer.IFuzzynorm,
	lexer.Intersects, lexer.IIntersects,
}

var comparisonLHS = []any{
	nil, true, false,
	int(5), int(-5), uint8(5), uint8(200), int64(-1), int64(5), uint64(5), uint64(math.MaxUint64),
	uint32(5), uint32(70000), uint16(5), uint16(65535), float64(5), float64(2.5), float64(math.NaN()),
	"abc", "", "ABC", "a.exe",
	net.ParseIP("10.0.0.1"), net.ParseIP("::1"),
	[]string{"a", "b"}, []string{}, []string{"A", "B", ""}, []string{"abc", "x"},
	[]uint64{1, 10}, []uint64{},
	struct{}{},
}

var comparisonRHS = []any{
	nil, true, false,
	int64(5), int64(-1), int64(6), int64(1) << 40, uint64(5), uint64(1) << 63, float64(5), float64(2.5),
	int32(5), int32(-1), uint32(5), uint16(5), uint8(5), int(5),
	"abc", "ABC", "a", "b", "", "5", "70000", "10.0.0", ".exe",
	[]string{"abc", "x"}, []string{"a"}, []string{"5", "70000"}, []string{}, []string{"A", "B"},
	net.ParseIP("10.0.0.1"), []net.IP{net.ParseIP("10.0.0.1")}, []uint16{5},
	struct{}{},
}

// recorded returns the results the comparisons gave when they were evaluated by
// walking the AST, which the compiled comparisons have replaced. The result is
// true, false or undefined, for each operator and the left operand, and for
// every right operand.
func recorded(t *testing.T) map[string][]any {
	t.Helper()
	data, err := os.ReadFile("testdata/compare.golden")
	require.NoError(t, err)
	rows := make(map[string][]any)
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		parts := strings.Fields(line)
		require.Len(t, parts, 3, line)
		results := make([]any, len(parts[2]))
		for i, c := range parts[2] {
			switch c {
			case 'T':
				results[i] = true
			case 'F':
				results[i] = false
			}
		}
		rows[parts[0]+" "+parts[1]] = results
	}
	return rows
}

func sameValue(a, b any) bool {
	return fmt.Sprintf("%T:%v", a, a) == fmt.Sprintf("%T:%v", b, b)
}

// TestComparisonMatchesRecordedResults compares the results of every operator
// on every pair of the operand types with the recorded ones. The cases the
// old evaluation got wrong are known, and listed with what the right result is.
func TestComparisonMatchesRecordedResults(t *testing.T) {
	rows := recorded(t)
	require.Len(t, rows, len(comparisonOps)*len(comparisonLHS))

	var checked int
	for _, op := range comparisonOps {
		for li, l := range comparisonLHS {
			row := rows[fmt.Sprintf("%s %d", op, li)]
			require.Len(t, row, len(comparisonRHS))
			for ri, r := range comparisonRHS {
				c := &Comparison{Op: op, LHS: &ConstEvaluator{Value: l}, RHS: &ConstEvaluator{Value: r}}
				got, want := c.Eval(nil), row[ri]
				checked++
				if sameValue(got, want) {
					continue
				}
				if known, ok := knownDeviation(op, l, r, got, want); ok {
					assert.True(t, known)
					continue
				}
				t.Errorf("%v %T(%v) %T(%v): got %T(%v), recorded %T(%v)", op, l, l, r, r, got, got, want, want)
			}
		}
	}
	t.Logf("%d comparisons checked", checked)
}

// knownDeviation tells the cases where the results differ because the recorded
// evaluation was wrong, not because the comparison is. They are listed here
// instead of reproduced.
func knownDeviation(op lexer.Token, l, r, got, want any) (bool, bool) {
	// IIN on the slice of strings fell through to the lone string comparison with
	// the empty string when no element of the list matched, so the slice with an
	// empty element matched any list.
	if ss, ok := l.([]string); ok && op == lexer.IIn {
		if _, isList := r.([]string); isList && want == true && got == false {
			for _, s := range ss {
				if s == "" {
					return true, true
				}
			}
		}
	}
	// an unsigned number compared with a signed one was converted to the type of
	// the unsigned one, which wrapped the negative or the oversized number around,
	// so MaxUint64 was equal to -1, and uint32(5) was greater than 1<<40.
	ln, lw, lok := toNumber(l)
	rn, _, rok := toNumber(r)
	if lok && rok && isOrdering(op) && ln.kind == kindUnsigned && rn.kind == kindSigned {
		max := map[width]uint64{wUint8: math.MaxUint8, wUint16: math.MaxUint16, wUint32: math.MaxUint32, wUint64: math.MaxUint64}[lw]
		if rn.i < 0 || uint64(rn.i) > max {
			return true, true
		}
	}
	return false, false
}

func TestComparisonUndefinedOperands(t *testing.T) {
	// an undefined operand is cast to false when the other one is a bool
	c := &Comparison{Op: lexer.Eq, LHS: &ConstEvaluator{}, RHS: &ConstEvaluator{Value: false}}
	assert.Equal(t, true, c.Eval(nil))
	c = &Comparison{Op: lexer.Neq, LHS: &ConstEvaluator{Value: true}, RHS: &ConstEvaluator{}}
	assert.Equal(t, true, c.Eval(nil))
	// and left undefined otherwise
	c = &Comparison{Op: lexer.Contains, LHS: &ConstEvaluator{}, RHS: &ConstEvaluator{Value: "a"}}
	assert.Nil(t, c.Eval(nil))
}
