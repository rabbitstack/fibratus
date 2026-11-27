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
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/util/entropy"
	"github.com/rabbitstack/fibratus/pkg/util/wildcard"
)

// LowerStringEvaluator evaluates the lower function, which converts the
// string to lower case.
type LowerStringEvaluator struct {
	EvaluatorBase
	Arg Evaluator
}

func (e *LowerStringEvaluator) Eval(ctx *EvalCtx) any {
	return strings.ToLower(strArg(ctx, e.Arg))
}

// UpperStringEvaluator evaluates the upper function, which converts the
// string to upper case.
type UpperStringEvaluator struct {
	EvaluatorBase
	Arg Evaluator
}

func (e *UpperStringEvaluator) Eval(ctx *EvalCtx) any {
	return strings.ToUpper(strArg(ctx, e.Arg))
}

// LtrimEvaluator evaluates the ltrim function, which removes the prefix from the string.
type LtrimEvaluator struct {
	EvaluatorBase
	Str, Prefix Evaluator
}

func (e *LtrimEvaluator) Eval(ctx *EvalCtx) any {
	return strings.TrimPrefix(strArg(ctx, e.Str), strArg(ctx, e.Prefix))
}

// RtrimEvaluator evaluates the rtrim function, which removes the suffix from the string.
type RtrimEvaluator struct {
	EvaluatorBase
	Str, Suffix Evaluator
}

func (e *RtrimEvaluator) Eval(ctx *EvalCtx) any {
	return strings.TrimSuffix(strArg(ctx, e.Str), strArg(ctx, e.Suffix))
}

// ReplaceEvaluator evaluates the replace function. The replacements are the
// pairs of the old and the new string, applied in order. Where there are
// more than one pair, they stop at the first one that isn't made of strings,
// and a trailing old string without the new one is ignored.
type ReplaceEvaluator struct {
	EvaluatorBase
	Str          Evaluator
	Replacements []Evaluator
}

func (e *ReplaceEvaluator) Eval(ctx *EvalCtx) any {
	s := strArg(ctx, e.Str)
	if len(e.Replacements) == 2 {
		return strings.ReplaceAll(s, strArg(ctx, e.Replacements[0]), strArg(ctx, e.Replacements[1]))
	}
	for i := 0; i+1 < len(e.Replacements); i += 2 {
		old, ok := e.Replacements[i].Eval(ctx).(string)
		if !ok {
			break
		}
		repl, ok := e.Replacements[i+1].Eval(ctx).(string)
		if !ok {
			break
		}
		s = strings.ReplaceAll(s, old, repl)
	}
	return s
}

// SplitEvaluator evaluates the split function, which splits the string
// by the separator.
type SplitEvaluator struct {
	EvaluatorBase
	Str, Sep Evaluator
}

func (e *SplitEvaluator) Eval(ctx *EvalCtx) any {
	return strings.Split(strArg(ctx, e.Str), strArg(ctx, e.Sep))
}

// SubstrEvaluator evaluates the substr function. The string is returned
// as it is if the bounds are out of its range.
type SubstrEvaluator struct {
	EvaluatorBase
	Str Evaluator
	// Start is the position of the first byte, and End the position that
	// the substring ends before. The End is nil for the rest of the string.
	Start, End Evaluator
}

func (e *SubstrEvaluator) Eval(ctx *EvalCtx) any {
	s := strArg(ctx, e.Str)
	start, ok := integer(e.Start.Eval(ctx))
	if !ok {
		return false
	}
	if e.End == nil {
		if start >= 0 && start < len(s) {
			return s[start:]
		}
		return s
	}
	end, ok := integer(e.End.Eval(ctx))
	if !ok {
		return false
	}
	if start >= 0 && end >= start && end < len(s) {
		return s[start:end]
	}
	return s
}

func integer(v any) (int, bool) {
	switch v := v.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	}
	return 0, false
}

// IndexOfEvaluator evaluates the indexof function, which returns the position of the
// substring. The order tells which position it is: first, any, last or lastany.
type IndexOfEvaluator struct {
	EvaluatorBase
	Str, Substr Evaluator
	// Order is nil for the first position
	Order Evaluator
}

func (e *IndexOfEvaluator) Eval(ctx *EvalCtx) any {
	s, substr := strArg(ctx, e.Str), strArg(ctx, e.Substr)
	if e.Order == nil {
		return strings.Index(s, substr)
	}
	switch strArg(ctx, e.Order) {
	case "first":
		return strings.Index(s, substr)
	case "any":
		return strings.IndexAny(s, substr)
	case "last":
		return strings.LastIndex(s, substr)
	case "lastany":
		return strings.LastIndexAny(s, substr)
	}
	return false
}

// LengthEvaluator evaluates the length function, which returns the number of
// the characters of the string, or the number of the elements of the slice.
type LengthEvaluator struct {
	EvaluatorBase
	Arg Evaluator
}

func (e *LengthEvaluator) Eval(ctx *EvalCtx) any {
	switch v := e.Arg.Eval(ctx).(type) {
	case string:
		return len([]rune(v))
	case []string:
		return len(v)
	}
	return -1
}

// ConcatEvaluator evaluates the concat function, which joins the strings and
// the integers. The values of any other type are skipped.
type ConcatEvaluator struct {
	EvaluatorBase
	Args []Evaluator
}

func (e *ConcatEvaluator) Eval(ctx *EvalCtx) any {
	var sb strings.Builder
	for _, arg := range e.Args {
		switch v := arg.Eval(ctx).(type) {
		case string:
			sb.WriteString(v)
		case int:
			sb.WriteString(strconv.FormatInt(int64(v), 10))
		case uint:
			sb.WriteString(strconv.FormatInt(int64(v), 10))
		case int8:
			sb.WriteString(strconv.FormatInt(int64(v), 10))
		case uint8:
			sb.WriteString(strconv.FormatInt(int64(v), 10))
		case int16:
			sb.WriteString(strconv.FormatInt(int64(v), 10))
		case uint16:
			sb.WriteString(strconv.FormatInt(int64(v), 10))
		case int32:
			sb.WriteString(strconv.FormatInt(int64(v), 10))
		case uint32:
			sb.WriteString(strconv.FormatInt(int64(v), 10))
		case int64:
			sb.WriteString(strconv.FormatInt(v, 10))
		case uint64:
			sb.WriteString(strconv.FormatInt(int64(v), 10))
		}
	}
	return sb.String()
}

// MD5Evaluator evaluates the md5 function, which returns the hex-encoded hash
// of a string or of the bytes.
type MD5Evaluator struct {
	EvaluatorBase
	Arg Evaluator
}

func (e *MD5Evaluator) Eval(ctx *EvalCtx) any {
	var data []byte
	switch v := e.Arg.Eval(ctx).(type) {
	case []byte:
		data = v
	case string:
		data = []byte(v)
	}
	if data == nil {
		return false
	}
	hash := md5.Sum(data)
	return hex.EncodeToString(hash[:])
}

// EntropyEvaluator evaluates the entropy function, which returns the entropy of
// the string. Shannon is the only algorithm.
type EntropyEvaluator struct {
	EvaluatorBase
	Str Evaluator
	// Algo is nil for the default algorithm
	Algo Evaluator
}

func (e *EntropyEvaluator) Eval(ctx *EvalCtx) any {
	s := strArg(ctx, e.Str)
	if e.Algo == nil {
		return entropy.Shannon(s)
	}
	switch strArg(ctx, e.Algo) {
	case "shannon":
		return entropy.Shannon(s)
	}
	return false
}

// CountEvaluator evaluates the count function, which counts the words
// of the string, or the elements of the slice, that match the wildcard pattern.
type CountEvaluator struct {
	EvaluatorBase
	Str, Pattern Evaluator
	// CaseInsensitive is nil if the match is case-insensitive
	CaseInsensitive Evaluator
}

func (e *CountEvaluator) Eval(ctx *EvalCtx) any {
	pattern := strArg(ctx, e.Pattern)
	caseInsensitive := true
	if e.CaseInsensitive != nil {
		caseInsensitive, _ = boolean(ctx, e.CaseInsensitive)
	}
	// the wildcard flag is whether the match is case-sensitive
	matches := func(s string) bool { return wildcard.Match(pattern, s, !caseInsensitive) }

	var count int
	switch v := e.Str.Eval(ctx).(type) {
	case string:
		for _, word := range strings.Fields(v) {
			if matches(word) {
				count++
			}
		}
	case []string:
		for _, s := range v {
			if matches(s) {
				count++
			}
		}
	}
	return count
}
