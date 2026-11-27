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
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/ast"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/compiler/lexer"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seg(variable, name string, s fields.Segment) *ast.BoundSegmentLiteral {
	return &ast.BoundSegmentLiteral{Value: variable + "." + name, BoundVar: ast.BareBoundVariableLiteral{Value: variable}, Segment: s}
}

// foreachOf compiles the foreach function over the collection.
func foreachOf(t *testing.T, collection any, variable string, predicate ast.Expr) *ForeachEvaluator {
	t.Helper()
	fn := &ast.Function{Name: "FOREACH", Args: []ast.Expr{
		&ast.FieldLiteral{Value: "ps.name"},
		&ast.BareBoundVariableLiteral{Value: variable},
		predicate,
	}}
	ev, err := newForeach(fn, &extractor{})
	require.NoError(t, err)
	e := ev.(*ForeachEvaluator)
	e.Iterable = &ConstEvaluator{Value: collection}
	return e
}

func TestForeachStrings(t *testing.T) {
	pred := bin(lexer.IMatches, &ast.BareBoundVariableLiteral{Value: "$s"}, &ast.StringLiteral{Value: "*NTDLL.dll"})

	ctx := AcquireEvalCtx()
	e := foreachOf(t, []string{"a.dll", "C:\\Windows\\ntdll.dll"}, "$s", pred)
	assert.Equal(t, true, e.Eval(ctx))

	e = foreachOf(t, []string{"a.dll", "b.dll"}, "$s", pred)
	assert.Equal(t, false, e.Eval(ctx))

	// nothing to iterate, or the collection can't be iterated
	assert.Equal(t, false, foreachOf(t, []string{}, "$s", pred).Eval(ctx))
	assert.Equal(t, false, foreachOf(t, nil, "$s", pred).Eval(ctx))
	assert.Equal(t, false, foreachOf(t, 42, "$s", pred).Eval(ctx))
}

func TestForeachProcesses(t *testing.T) {
	procs := []*pstypes.PS{
		{PID: 4, Name: "System", Exe: "System"},
		{PID: 700, Name: "services.exe", Exe: "C:\\Windows\\services.exe", Cmdline: "services.exe"},
	}
	pred := bin(lexer.And,
		bin(lexer.Eq, seg("$p", "name", fields.NameSegment), &ast.StringLiteral{Value: "services.exe"}),
		bin(lexer.Gt, seg("$p", "pid", fields.PIDSegment), &ast.IntegerLiteral{Value: 100}),
	)
	ctx := AcquireEvalCtx()
	assert.Equal(t, true, foreachOf(t, procs, "$p", pred).Eval(ctx))

	pred = bin(lexer.Eq, seg("$p", "name", fields.NameSegment), &ast.StringLiteral{Value: "lsass.exe"})
	assert.Equal(t, false, foreachOf(t, procs, "$p", pred).Eval(ctx))
}

func TestForeachMmaps(t *testing.T) {
	mmaps := []pstypes.Mmap{{Size: 4096, File: "/lib/libc.so"}, {Size: 8192, File: "/lib/libm.so"}}
	pred := bin(lexer.And,
		bin(lexer.Eq, seg("$m", "size", fields.SizeSegment), &ast.IntegerLiteral{Value: 8192}),
		bin(lexer.Endswith, seg("$m", "path", fields.PathSegment), &ast.StringLiteral{Value: "libm.so"}),
	)
	ctx := AcquireEvalCtx()
	assert.Equal(t, true, foreachOf(t, mmaps, "$m", pred).Eval(ctx))
}

// The values of the element must not outlive the loop, since the context is shared
// with the rest of the rules evaluated for the event.
func TestForeachUnbindsTheElement(t *testing.T) {
	pred := bin(lexer.Eq, &ast.BareBoundVariableLiteral{Value: "$s"}, &ast.StringLiteral{Value: "b"})
	ctx := AcquireEvalCtx()
	e := foreachOf(t, []string{"a", "b", "c"}, "$s", pred)
	assert.Equal(t, true, e.Eval(ctx))
	assert.NotContains(t, ctx.Values, "$s")

	// the attribute the element doesn't have is not the one of the previous element
	pred = bin(lexer.Eq, seg("$p", "cwd", fields.CwdSegment), &ast.StringLiteral{Value: "/tmp"})
	e = foreachOf(t, []*pstypes.PS{{Cwd: "/tmp"}, {Cwd: "/home"}}, "$p", pred)
	assert.Equal(t, true, e.Eval(ctx))
	assert.NotContains(t, ctx.Values, "$p.cwd")
}
