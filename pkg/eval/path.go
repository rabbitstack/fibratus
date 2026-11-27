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
	"strings"
)

// BaseEvaluator evaluates the base function, which returns the last element
// of the path, or of every path of the slice. The extension is removed if the
// optional argument is false.
type BaseEvaluator struct {
	EvaluatorBase
	Path Evaluator
	// Ext tells whether to keep the extension. It is nil to keep it.
	Ext Evaluator
}

func (e *BaseEvaluator) Eval(ctx *EvalCtx) any {
	switch p := e.Path.Eval(ctx).(type) {
	case string:
		return e.trimExt(ctx, filepath.Base(p))
	case []string:
		paths := make([]string, len(p))
		for i, path := range p {
			paths[i] = e.trimExt(ctx, filepath.Base(path))
		}
		return paths
	}
	return nil
}

func (e *BaseEvaluator) trimExt(ctx *EvalCtx, base string) string {
	if e.Ext == nil {
		return base
	}
	if keep, ok := boolean(ctx, e.Ext); ok && !keep {
		if n := strings.LastIndex(base, "."); n > 0 {
			return base[:n]
		}
	}
	return base
}

// DirEvaluator evaluates the dir function, which returns all but the last
// element of the path, or of every path of the slice.
type DirEvaluator struct {
	EvaluatorBase
	Path Evaluator
}

func (e *DirEvaluator) Eval(ctx *EvalCtx) any {
	switch p := e.Path.Eval(ctx).(type) {
	case string:
		return filepath.Dir(p)
	case []string:
		dirs := make([]string, len(p))
		for i, path := range p {
			dirs[i] = filepath.Dir(path)
		}
		return dirs
	}
	return nil
}

// ExtEvaluator evaluates the ext function, which returns the file extension.
// The leading dot is removed if the optional argument is false.
type ExtEvaluator struct {
	EvaluatorBase
	Path Evaluator
	// Dot tells whether to keep the dot. It is nil to keep it.
	Dot Evaluator
}

func (e *ExtEvaluator) Eval(ctx *EvalCtx) any {
	ext := filepath.Ext(strArg(ctx, e.Path))
	if keep, ok := boolean(ctx, e.Dot); ok && !keep && ext != "" {
		return ext[1:]
	}
	return ext
}

// GlobEvaluator evaluates the glob function, which returns the names of the
// files that match the pattern.
type GlobEvaluator struct {
	EvaluatorBase
	Pattern Evaluator
}

func (e *GlobEvaluator) Eval(ctx *EvalCtx) any {
	matches, err := filepath.Glob(strArg(ctx, e.Pattern))
	if err != nil {
		return nil
	}
	return matches
}

// IsAbsEvaluator evaluates the is_abs function, which tells if the path is absolute.
type IsAbsEvaluator struct {
	EvaluatorBase
	Path Evaluator
}

func (e *IsAbsEvaluator) Eval(ctx *EvalCtx) any {
	return filepath.IsAbs(strArg(ctx, e.Path))
}

// VolumeEvaluator evaluates the volume function, which returns the leading
// volume name of the path.
type VolumeEvaluator struct {
	EvaluatorBase
	Path Evaluator
}

func (e *VolumeEvaluator) Eval(ctx *EvalCtx) any {
	return filepath.VolumeName(strArg(ctx, e.Path))
}

// SymlinkEvaluator evaluates the symlink function, which returns the path
// the symbolic link points to. The path itself is returned if it isn't a link.
type SymlinkEvaluator struct {
	EvaluatorBase
	Path Evaluator
}

func (e *SymlinkEvaluator) Eval(ctx *EvalCtx) any {
	path := strArg(ctx, e.Path)
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return target
}
