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
	"net"
	"path/filepath"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/compiler/functions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// call evaluates the function that is called with the arguments as the literals.
func call(t *testing.T, fn functions.Fn, args ...any) any {
	t.Helper()
	evs := make([]Evaluator, len(args))
	for i, arg := range args {
		evs[i] = &ConstEvaluator{Value: arg}
	}
	ev, err := newFunction(fn, evs)
	require.NoError(t, err)
	return ev.Eval(AcquireEvalCtx())
}

func TestStringFunctions(t *testing.T) {
	var tests = []struct {
		fn       functions.Fn
		args     []any
		expected any
	}{
		{functions.LowerFn, []any{"HellO World"}, "hello world"},
		{functions.UpperFn, []any{"HellO World"}, "HELLO WORLD"},
		{functions.LtrimFn, []any{"hello world", "hello "}, "world"},
		{functions.RtrimFn, []any{"hello world", " world"}, "hello"},

		{functions.ReplaceFn, []any{"hello world", "hello", "hell"}, "hell world"},
		{functions.ReplaceFn, []any{"hello world", "hello", "hell", "NO", "REPL"}, "hell world"},
		{functions.ReplaceFn, []any{"hello world", "hello", "hell", "hell", "heaven", "world", "brave"}, "heaven brave"},
		{functions.ReplaceFn, []any{"HKEY_LOCAL_MACHINE\\SAM", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER\\Console", "HKCU"}, "HKLM\\SAM"},
		{functions.ReplaceFn, []any{"HKEY_CURRENT_USER\\Console", "HKEY_LOCAL_MACHINE", "HKLM", "HKEY_CURRENT_USER", "HKCU"}, "HKCU\\Console"},

		{functions.SplitFn, []any{"Hello World", " "}, []string{"Hello", "World"}},

		{functions.SubstrFn, []any{"Hello", 0, 4}, "Hell"},
		{functions.SubstrFn, []any{"Hello World!", 0, 50}, "Hello World!"},
		{functions.SubstrFn, []any{"Hello World!", 4, -1}, "Hello World!"},
		{functions.SubstrFn, []any{"Hello World!", -1, 10}, "Hello World!"},
		{functions.SubstrFn, []any{"Hello World!", 6, 7}, "W"},
		{functions.SubstrFn, []any{"Hello World!", 6}, "World!"},
		{functions.SubstrFn, []any{"Hello World!", 20}, "Hello World!"},
		{functions.SubstrFn, []any{"Hello World!", "x"}, false},

		{functions.IndexOfFn, []any{"hello world", "world"}, 6},
		{functions.IndexOfFn, []any{"hello world", "brave"}, -1},
		{functions.IndexOfFn, []any{"hello world brave world", "world", "last"}, 18},
		{functions.IndexOfFn, []any{"hello world", "ow", "any"}, 4},
		{functions.IndexOfFn, []any{"hello world", "ow", "lastany"}, 7},
		{functions.IndexOfFn, []any{"hello world", "ow", "nope"}, false},

		{functions.LengthFn, []any{"hello"}, 5},
		{functions.LengthFn, []any{"こんにちは"}, 5},
		{functions.LengthFn, []any{[]string{"hello", "world"}}, 2},
		{functions.LengthFn, []any{42}, -1},

		{functions.ConcatFn, []any{"hello ", "world", " ", int32(7), 7}, "hello world 77"},

		{functions.MD5Fn, []any{`HKEY_LOCAL_MACHINE\SYSTEM\Setup\Pid`}, "eab870b2a516206575d2ffa2b98d8af5"},
		{functions.MD5Fn, []any{5}, false},

		{functions.EntropyFn, []any{"\\Device\\HarddiskVolume2\\Windows\\system32\\user32.dll"}, 255},
		{functions.EntropyFn, []any{"abc", "other"}, false},

		{functions.CountFn, []any{"hello world", "?orld"}, 1},
		{functions.CountFn, []any{"hello world", "saturn"}, 0},
		{functions.CountFn, []any{[]string{"C:\\Windows\\System32\\ntdll.dll", "C:\\Windows\\System32\\NTDLL.dll"}, "*ntdll.dll"}, 2},
		{functions.CountFn, []any{[]string{"C:\\Windows\\System32\\ntdll.dll", "C:\\Windows\\System32\\NTDLL.dll"}, "*ntdll.dll", false}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.fn.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, call(t, tt.fn, tt.args...), "%s%v", tt.fn, tt.args)
		})
	}
}

func TestRegexFunction(t *testing.T) {
	assert.Equal(t, true, call(t, functions.RegexFn, "powershell.exe", "power.*(shell|hell).exe"))
	assert.Equal(t, true, call(t, functions.RegexFn, "powershell.exe", "power.*(shell|hell).dll", ".*hell.exe"))
	assert.Equal(t, false, call(t, functions.RegexFn, "powershell.exe", "[`"))
	assert.Equal(t, false, call(t, functions.RegexFn, "powershell.exe", "bash"))

	// the patterns are compiled with the function
	ev, err := newFunction(functions.RegexFn, []Evaluator{
		&ConstEvaluator{Value: "powershell.exe"}, &ConstEvaluator{Value: "power.*"}, &ConstEvaluator{Value: "[`"},
	})
	require.NoError(t, err)
	assert.Len(t, ev.(*RegexEvaluator).Regexps, 1)
}

func TestCIDRContainsFunction(t *testing.T) {
	var tests = []struct {
		args     []any
		expected any
	}{
		{[]any{net.ParseIP("192.168.1.5"), "192.168.1.0/24"}, true},
		{[]any{net.ParseIP("216.58.201.174"), "216.58.201.1/24"}, true},
		{[]any{"192.168.1.5", "192.168.1.0/24"}, true},
		{[]any{net.ParseIP("192.168.1.5"), "172.168.1.0/24"}, false},
		{[]any{net.ParseIP("192.168.1.5"), "172.168.1.0/24", "192.168.1.0/24"}, true},
		{[]any{net.ParseIP("192.168.1.5"), "192.168.1.0"}, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, call(t, functions.CIDRContainsFn, tt.args...), "%v", tt.args)
	}

	// the network that is not a literal is parsed for the event
	ev, err := newFunction(functions.CIDRContainsFn, []Evaluator{
		&ConstEvaluator{Value: net.ParseIP("10.1.2.3")},
		&ConstEvaluator{Value: 5}, // not a network, skipped
		&call2{cidr: "10.0.0.0/8"},
	})
	require.NoError(t, err)
	assert.Equal(t, true, ev.Eval(AcquireEvalCtx()))
}

// call2 is the evaluator that isn't a literal.
type call2 struct {
	EvaluatorBase
	cidr string
}

func (c *call2) Eval(*EvalCtx) any { return c.cidr }

func TestPathFunctions(t *testing.T) {
	p := filepath.Join("a", "b", "cmd.exe")
	var tests = []struct {
		fn       functions.Fn
		args     []any
		expected any
	}{
		{functions.BaseFn, []any{p}, "cmd.exe"},
		{functions.BaseFn, []any{p, false}, "cmd"},
		{functions.BaseFn, []any{[]string{p, filepath.Join("x", "y.dll")}, false}, []string{"cmd", "y"}},
		{functions.BaseFn, []any{5}, nil},
		{functions.DirFn, []any{p}, filepath.Join("a", "b")},
		{functions.DirFn, []any{[]string{p}}, []string{filepath.Join("a", "b")}},
		{functions.ExtFn, []any{p}, ".exe"},
		{functions.ExtFn, []any{p, false}, "exe"},
		{functions.ExtFn, []any{"noext", false}, ""},
		{functions.IsAbsFn, []any{"relative"}, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, call(t, tt.fn, tt.args...), "%s%v", tt.fn, tt.args)
	}
}

func TestGlobFunction(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, writeFile(filepath.Join(dir, "notepad.exe")))
	res := call(t, functions.GlobFn, filepath.Join(dir, "*.exe"))
	assert.Equal(t, []string{filepath.Join(dir, "notepad.exe")}, res)
}

func TestSymlinkFunction(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	require.NoError(t, writeFile(target))
	ln := filepath.Join(dir, "symlink.txt")
	require.NoError(t, symlink("target.txt", ln))
	res, ok := call(t, functions.SymlinkFn, ln).(string)
	require.True(t, ok)
	assert.Equal(t, "target.txt", filepath.Base(res))
	// a path that is not a link is returned as it is
	assert.Equal(t, filepath.Join(dir, "missing"), call(t, functions.SymlinkFn, filepath.Join(dir, "missing")))
}

func TestFunctionRequiresItsArguments(t *testing.T) {
	_, err := newFunction(functions.ReplaceFn, []Evaluator{&ConstEvaluator{Value: "a"}})
	assert.Error(t, err)
	_, err = newFunction(functions.Fn(0), nil)
	assert.Error(t, err)
}

func TestFunctionsInExpressions(t *testing.T) {
	evt := treeTestEvent()
	var tests = []struct {
		expr     string
		expected bool
	}{
		{`lower(evt.host) = 'kitty'`, true},
		{`upper(evt.host) = 'KITTY'`, true},
		{`upper(evt.host) = 'kitty'`, false},
		{`length(evt.host) = 5`, true},
		{`length(evt.host) >= 6`, false},
		{`concat(evt.host, '-', evt.pid) = 'kitty-1023'`, true},
		{`substr(evt.host, 0, 2) = 'ki'`, true},
		{`regex(evt.host, 'k.*y')`, true},
		{`not regex(evt.host, 'k.*y')`, false},
		{`not regex(evt.host, 'x')`, true},
		{`regex(lower(evt.host), 'k.*y') and evt.pid = 1023`, true},
		{`indexof(evt.host, 'tt') = 2`, true},
		{`lower(upper(evt.host)) = 'kitty'`, true},
	}
	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			p, err := NewProgram("t", tt.expr)
			require.NoError(t, err)
			got, _ := evalProgram(p, evt)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// Every function the parser accepts has to have the evaluator.
func TestEveryFunctionOfTheCatalogHasAnEvaluator(t *testing.T) {
	for _, name := range functions.Names() {
		fn, ok := functions.Parse(name)
		require.True(t, ok, name)
		desc, _ := functions.Lookup(name)
		if fn == functions.ForeachFn {
			continue // compiled from the expression
		}
		if fn == functions.YaraFn {
			// the signature rejects the call when built without yara,
			// so the evaluator is never asked for
			continue
		}
		assert.Equal(t, desc.RequiredArgs(), minArgs[fn], "%s requires as many arguments as its signature says", name)

		args := make([]Evaluator, desc.RequiredArgs())
		for i := range args {
			args[i] = &ConstEvaluator{Value: "x"}
		}
		ev, err := newFunction(fn, args)
		assert.NoError(t, err, name)
		assert.NotNil(t, ev, name)
	}
}
