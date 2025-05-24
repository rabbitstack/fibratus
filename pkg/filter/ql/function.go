/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package ql

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"golang.org/x/sys/windows"
	"maps"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/filter/ql/functions"
)

var (
	// ErrArgumentTypeMismatch signals an invalid argument type
	ErrArgumentTypeMismatch = func(i int, keyword string, fn functions.Fn, types []functions.ArgType) error {
		argTypes := make([]string, len(types))
		for i, typ := range types {
			argTypes[i] = typ.String()
		}
		return fmt.Errorf("argument #%d (%s) in function %s should be one of: %v", i+1, keyword, fn, strings.Join(argTypes, "|"))
	}
	// ErrUndefinedFunction is thrown when an unknown function is supplied
	ErrUndefinedFunction = func(name string) error {
		return fmt.Errorf("%s function is undefined. Did you mean one of %s%s", name, strings.Join(functionNames(), "|"), "?")
	}
	// ErrFunctionSignature is thrown when the function signature is not satisfied
	ErrFunctionSignature = func(desc functions.FunctionDesc, givenArguments int) error {
		return fmt.Errorf("%s function requires %d argument(s) but %d argument(s) given", desc.Name, desc.RequiredArgs(), givenArguments)
	}
)

var funcs = map[string]FunctionDef{
	functions.CIDRContainsFn.String(): &functions.CIDRContains{},
	functions.MD5Fn.String():          &functions.MD5{},
	functions.ConcatFn.String():       &functions.Concat{},
	functions.LtrimFn.String():        &functions.Ltrim{},
	functions.RtrimFn.String():        &functions.Rtrim{},
	functions.LowerFn.String():        &functions.Lower{},
	functions.UpperFn.String():        &functions.Upper{},
	functions.ReplaceFn.String():      &functions.Replace{},
	functions.SplitFn.String():        &functions.Split{},
	functions.LengthFn.String():       &functions.Length{},
	functions.IndexOfFn.String():      &functions.IndexOf{},
	functions.SubstrFn.String():       &functions.Substr{},
	functions.EntropyFn.String():      &functions.Entropy{},
	functions.RegexFn.String():        functions.NewRegex(),
	functions.IsMinidumpFn.String():   &functions.IsMinidump{},
	functions.BaseFn.String():         &functions.Base{},
	functions.DirFn.String():          &functions.Dir{},
	functions.SymlinkFn.String():      &functions.Symlink{},
	functions.ExtFn.String():          &functions.Ext{},
	functions.GlobFn.String():         &functions.Glob{},
	functions.IsAbsFn.String():        &functions.IsAbs{},
	functions.VolumeFn.String():       &functions.Volume{},
	functions.GetRegValueFn.String():  &functions.GetRegValue{},
	functions.YaraFn.String():         &functions.Yara{},
	functions.ForeachFn.String():      &Foreach{},
}

// FunctionDef is the interface that all function definitions have to satisfy.
type FunctionDef interface {
	// Call is the main function method that contains the implementation logic.
	Call(args []interface{}) (interface{}, bool)
	// Desc returns the function descriptor.
	Desc() functions.FunctionDesc
	// Name returns the function name.
	Name() functions.Fn
}

// FunctionValuer implements the CallValuer interface and delegates
// the evaluation of function calls to the corresponding functions.
type FunctionValuer struct {
	m map[string]interface{}
}

func (f FunctionValuer) Value(key string) (interface{}, bool) {
	v, ok := f.m[key]
	return v, ok
}

func (FunctionValuer) Call(name string, args []interface{}) (interface{}, bool) {
	fn, ok := funcs[strings.ToUpper(name)]
	if !ok {
		return nil, false
	}
	return fn.Call(args)
}

func functionNames() []string {
	names := make([]string, 0, len(funcs))
	for _, f := range funcs {
		names = append(names, f.Name().String())
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	return names
}

// Foreach adds iteration capabilities to the rule language. The decision
// to keep the function implementation outside the functions package is
// deliberate.
// The function mostly operates with raw expressions, and if the function
// lived in the functions package, that would create a cyclic import and
// likely unleash more painful side effects. For the sake of simplicity
// it is better to keep the function close to the parser and AST evaluation.
// Foreach accepts three required and multiple optional arguments. The
// first argument is the iterable value typically yielded by the pseudo
// field. The function recognizes process internal state collections such
// as modules, threads, memory mappings, or thread stack frames. Obviously,
// it is also possible to iterate over a simple string slice.
// The second argument represents the bound variable which is an item
// associated with every element in the slice. The bound variable is
// accessed in the third argument, the predicate. It is usually followed by
// the segment that denotes the accessed value. Unsurprisingly, the
// predicate is commonly a binary expression which can be formed of not/paren
// expressions, other functions, and so on. The predicate is executed on
// every item in the slice. If the predicate evaluates to true, the function
// also returns the true value.
// Lastly, foreach function can receive an optional list of fields from the
// outer context, i.e. outside predicate loop. Therefore, for the predicate
// to access the field not defined within the scope of the iterable, it must
// capture the field first.
//
// Some examples:
//
//   - Traverses process modules and return true if the module path matches the pattern
//     foreach(ps._modules, $mod, $mod.path imatches '?:\\Windows\\System32\\us?r32.dll')
//
//   - For each process ancestor, checks if the ancestor is services.exe and the current process is protected
//     foreach(ps._ancestors, $proc, $proc.name = 'services.exe' and ps.is_protected, ps.is_protected)
//     In this example, the ps.is_protected field is captured prior to its usage in the predicate
type Foreach struct{}

func (f *Foreach) Call(args []interface{}) (interface{}, bool) {
	if len(args) < 3 {
		return false, false
	}

	s := args[0] // iterable (slice or map)
	if s == nil {
		return false, false
	}

	v, ok := args[1].(*BareBoundVariableLiteral) // item (variable)
	if !ok {
		return false, false
	}

	e := args[2] // predicate (expression)
	if e == nil {
		return false, false
	}

	var valuer = MapValuer{}
	if len(args) > 3 { // optional predicate captures
		for i := 3; i < len(args); i++ {
			m, ok := args[i].(MapValuer)
			if !ok {
				continue
			}
			maps.Copy(valuer, m)
		}
	}

	segments := make([]*BoundSegmentLiteral, 0)

	// obtain bound segments used in expression
	var useCallValuer bool
	walk := func(n Node) {
		switch exp := n.(type) {
		case *BoundSegmentLiteral:
			segments = append(segments, exp)
		case *Function:
			useCallValuer = true
		}
	}

	switch expr := e.(type) {
	case *BinaryExpr:
		WalkFunc(expr, walk)
	case *NotExpr:
		WalkFunc(expr, walk)
	}

	switch elems := s.(type) {
	case []string:
		for _, elem := range elems {
			if f.evalExpr(e, useCallValuer, f.stringMapValuer(v, elem), valuer) {
				return true, true
			}
		}
	case []*pstypes.PS:
		for _, proc := range elems {
			if f.evalExpr(e, useCallValuer, f.procMapValuer(segments, proc), valuer) {
				return true, true
			}
		}
	case []pstypes.Module:
		for _, mod := range elems {
			if f.evalExpr(e, useCallValuer, f.moduleMapValuer(segments, mod), valuer) {
				return true, true
			}
		}
	case map[uint32]pstypes.Thread:
		for _, thread := range elems {
			if f.evalExpr(e, useCallValuer, f.threadMapValuer(segments, thread), valuer) {
				return true, true
			}
		}
	case []pstypes.Mmap:
		for _, mmap := range elems {
			if f.evalExpr(e, useCallValuer, f.mmapMapValuer(segments, mmap), valuer) {
				return true, true
			}
		}
	case []pe.Sec:
		for _, sec := range elems {
			if f.evalExpr(e, useCallValuer, f.sectionMapValuer(segments, sec), valuer) {
				return true, true
			}
		}
	case callstack.Callstack:
		var pid uint32
		var proc windows.Handle
		var err error

		if !elems.IsEmpty() {
			pid = elems.FrameAt(0).PID
		}

		// open process handle with required access mask
		var desiredAccess uint32
	loop:
		for _, seg := range segments {
			switch seg.Segment {
			case fields.CallsiteLeadingAssemblySegment, fields.CallsiteTrailingAssemblySegment:
				// break on broader access rights
				desiredAccess = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
				break loop
			case fields.AllocationSizeSegment, fields.ProtectionSegment:
				desiredAccess = windows.PROCESS_QUERY_INFORMATION
			}
		}
		if desiredAccess != 0 {
			proc, err = windows.OpenProcess(desiredAccess, false, pid)
			if err != nil {
				return false, false
			}
			defer windows.Close(proc)
		}

		for _, frame := range elems {
			if f.evalExpr(e, useCallValuer, f.callstackMapValuer(segments, frame, proc), valuer) {
				return true, true
			}
		}
	}

	return false, false
}

func (f *Foreach) Desc() functions.FunctionDesc {
	desc := functions.FunctionDesc{
		Name: functions.ForeachFn,
		Args: []functions.FunctionArgDesc{
			{Keyword: "iterable", Types: []functions.ArgType{functions.Field}, Required: true},
			{Keyword: "var", Types: []functions.ArgType{functions.BareBoundVariable}, Required: true},
			{Keyword: "predicate", Types: []functions.ArgType{functions.Expression}, Required: true},
		},
		ArgsValidationFunc: func(args []string) error {
			s := args[0] // slice/map field name
			v := args[1] // bound variable name
			e := args[2] // expression

			var reserved = map[string]bool{ // reserved bound variable names
				"$ps":         true,
				"$pe":         true,
				"$file":       true,
				"$image":      true,
				"$thread":     true,
				"$threadpool": true,
				"$registry":   true,
				"$net":        true,
				"$mem":        true,
				"$handle":     true,
				"$dns":        true,
				"$evt":        true,
			}

			if reserved[v] {
				return fmt.Errorf("%q is a reserved bound variable name", v)
			}

			var hasBoundVar bool
			var boundSegmentRegexp = regexp.MustCompile(`(\$[a-zA-Z_0-9]+)\.?([a-zA-Z0-9_.$]*)`)

			// scan all bound fields inside expression
			matches := boundSegmentRegexp.FindAllStringSubmatch(e, -1)

			for _, match := range matches {
				// check the bound variable references
				// a valid segment and also verify if
				// the declared bound item is used in
				// the predicate
				switch len(match) {
				case 3:
					if match[2] != "" && !fields.IsSegmentAllowed(fields.Field(s), fields.Segment(match[2])) {
						return fmt.Errorf("unrecognized property %q accessing bound variable %s. Allowed properties [%s]",
							match[2],
							v,
							fields.SegmentsHint(fields.Field(s)))
					}
					if match[1] == v {
						hasBoundVar = true
					}
					if match[1] != v {
						return fmt.Errorf("undeclared bound variable %s in predicate %q", match[1], e)
					}
				default:
					return fmt.Errorf("invalid bound variables in predicate %q", e)
				}
			}

			if !hasBoundVar {
				return fmt.Errorf("unused bound variable %s in predicate %q", v, e)
			}

			var fieldRegexp = regexp.MustCompile(`(ps|pe|file|image|thread|registry|net|mem|handle|dns|evt)\.[a-zA-Z0-9_.$]+`)
			matches = fieldRegexp.FindAllStringSubmatch(e, -1)

			if len(args) > 3 {
				// validate predicate captures. The basic
				// requirements must ensure the field is
				// captured from outer context before it
				// can be used in the predicate
				captures := make(map[string]bool)

				for n := 3; n < len(args); n++ {
					captures[args[n]] = true
				}

				for _, match := range matches {
					if len(match) != 2 {
						continue
					}
					if !captures[match[0]] {
						return fmt.Errorf("field %s used in predicate %q but not captured", match[0], e)
					}
				}

				if len(matches) == 0 && len(captures) > 0 {
					return fmt.Errorf("one of captured field(s) (%s) not used in predicate %q", strings.Join(args[3:], ","), e)
				}
			} else {
				for _, match := range matches {
					if len(match) != 2 {
						continue
					}
					return fmt.Errorf("field %s used in predicate %q but not captured", match[0], e)
				}
			}

			return nil
		},
	}

	offset := len(desc.Args)

	// add optional fields the predicate can capture. Ten fields should be enough for anybody ;)
	for i := offset; i < offset+10; i++ {
		desc.Args = append(desc.Args, functions.FunctionArgDesc{Keyword: "field", Types: []functions.ArgType{functions.Field}})
	}

	return desc
}

func (f *Foreach) Name() functions.Fn {
	return functions.ForeachFn
}

func (f *Foreach) evalExpr(e any, useCallValuer bool, valuers ...Valuer) bool {
	var valuer ValuerEval

	if useCallValuer {
		callValuerMap := make(map[string]interface{})
		for _, v := range valuers {
			if m, ok := v.(MapValuer); ok {
				maps.Copy(callValuerMap, m)
			}
		}
		valuer = ValuerEval{Valuer: MultiValuer(append([]Valuer{FunctionValuer{callValuerMap}}, valuers...)...)}
	} else {
		valuer = ValuerEval{Valuer: MultiValuer(valuers...)}
	}

	switch expr := e.(type) {
	case *BinaryExpr:
		v, ok := valuer.Eval(expr).(bool)
		if !ok {
			return false
		}
		return v
	case *NotExpr:
		v, ok := valuer.Eval(expr).(bool)
		if !ok {
			return false
		}
		return v
	}

	return false
}

// stringMapValuer returns the map valuer composed of primitive string values.
func (f *Foreach) stringMapValuer(v *BareBoundVariableLiteral, s string) MapValuer {
	return MapValuer{v.Value: s}
}

// moduleMapValuer returns the map valuer with process module attributes.
func (f *Foreach) moduleMapValuer(segments []*BoundSegmentLiteral, mod pstypes.Module) MapValuer {
	var valuer = MapValuer{}
	for _, seg := range segments {
		key := seg.Value
		switch seg.Segment {
		case fields.PathSegment:
			valuer[key] = mod.Name
		case fields.NameSegment:
			valuer[key] = filepath.Base(mod.Name)
		case fields.AddressSegment:
			valuer[key] = mod.BaseAddress.String()
		case fields.SizeSegment:
			valuer[key] = mod.Size
		case fields.ChecksumSegment:
			valuer[key] = mod.Checksum
		}
	}
	return valuer
}

// procMapValuer returns the map valuer with process attributes.
func (f *Foreach) procMapValuer(segments []*BoundSegmentLiteral, proc *pstypes.PS) MapValuer {
	var valuer = MapValuer{}
	for _, seg := range segments {
		key := seg.Value
		switch seg.Segment {
		case fields.PIDSegment:
			valuer[key] = proc.PID
		case fields.NameSegment:
			valuer[key] = proc.Name
		case fields.ExeSegment:
			valuer[key] = proc.Exe
		case fields.CmdlineSegment:
			valuer[key] = proc.Cmdline
		case fields.ArgsSegment:
			valuer[key] = proc.Args
		case fields.CwdSegment:
			valuer[key] = proc.Cwd
		case fields.SIDSegment:
			valuer[key] = proc.SID
		case fields.SessionIDSegment:
			valuer[key] = proc.SessionID
		case fields.UsernameSegment:
			valuer[key] = proc.Username
		case fields.DomainSegment:
			valuer[key] = proc.Domain
		}
	}
	return valuer
}

// threadMapValuer returns the map valuer with thread information.
func (f *Foreach) threadMapValuer(segments []*BoundSegmentLiteral, thread pstypes.Thread) MapValuer {
	var valuer = MapValuer{}
	for _, seg := range segments {
		key := seg.Value
		switch seg.Segment {
		case fields.TidSegment:
			valuer[key] = thread.Tid
		case fields.StartAddressSegment:
			valuer[key] = thread.StartAddress.String()
		case fields.UserStackBaseSegment:
			valuer[key] = thread.UstackBase.String()
		case fields.UserStackLimitSegment:
			valuer[key] = thread.UstackLimit.String()
		case fields.KernelStackBaseSegment:
			valuer[key] = thread.KstackBase.String()
		case fields.KernelStackLimitSegment:
			valuer[key] = thread.KstackLimit.String()
		}
	}
	return valuer
}

// mmapMapValuer returns map valuer with memory mapping details.
func (f *Foreach) mmapMapValuer(segments []*BoundSegmentLiteral, mmap pstypes.Mmap) MapValuer {
	var valuer = MapValuer{}
	for _, seg := range segments {
		key := seg.Value
		switch seg.Segment {
		case fields.AddressSegment:
			valuer[key] = mmap.BaseAddress.String()
		case fields.SizeSegment:
			valuer[key] = mmap.Size
		case fields.ProtectionSegment:
			valuer[key] = mmap.ProtectMask()
		case fields.TypeSegment:
			valuer[key] = mmap.Type
		case fields.PathSegment:
			valuer[key] = mmap.File
		}
	}
	return valuer
}

// callstackMapValuer returns map valuer with thread stack frame data.
func (f *Foreach) callstackMapValuer(segments []*BoundSegmentLiteral, frame callstack.Frame, proc windows.Handle) MapValuer {
	var valuer = MapValuer{}
	for _, seg := range segments {
		key := seg.Value
		switch seg.Segment {
		case fields.AddressSegment:
			valuer[key] = frame.Addr.String()
		case fields.OffsetSegment:
			valuer[key] = frame.Offset
		case fields.IsUnbackedSegment:
			valuer[key] = frame.IsUnbacked()
		case fields.ModuleSegment:
			valuer[key] = frame.Module
		case fields.SymbolSegment:
			valuer[key] = frame.Module + "!" + frame.Symbol
		case fields.AllocationSizeSegment:
			valuer[key] = frame.AllocationSize(proc)
		case fields.ProtectionSegment:
			valuer[key] = frame.Protection(proc)
		case fields.CallsiteTrailingAssemblySegment:
			valuer[key] = frame.CallsiteAssembly(proc, false)
		case fields.CallsiteLeadingAssemblySegment:
			valuer[key] = frame.CallsiteAssembly(proc, true)
		case fields.ModuleSignatureIsSignedSegment, fields.ModuleSignatureIsTrustedSegment,
			fields.ModuleSignatureCertIssuerSegment, fields.ModuleSignatureCertSubjectSegment:

			if frame.ModuleAddress.IsZero() {
				continue
			}

			segment := seg.Segment
			sign := signature.GetSignatures().GetSignature(frame.ModuleAddress.Uint64())
			if sign == nil && frame.Module != "" {
				// register signature if not present in the cache
				var err error
				sign = &signature.Signature{Filename: frame.Module}
				sign.Type, sign.Level, err = sign.Check()
				if err != nil {
					continue
				}

				if sign.IsSigned() {
					sign.Verify()
				}

				if segment == fields.ModuleSignatureCertIssuerSegment || segment == fields.ModuleSignatureCertSubjectSegment {
					if err := sign.ParseCertificate(); err != nil {
						continue
					}
				}

				signature.GetSignatures().PutSignature(frame.ModuleAddress.Uint64(), sign)
			}

			switch segment {
			case fields.ModuleSignatureIsSignedSegment:
				valuer[key] = sign.IsSigned()
			case fields.ModuleSignatureIsTrustedSegment:
				valuer[key] = sign.IsTrusted()
			case fields.ModuleSignatureCertIssuerSegment:
				if err := sign.ParseCertificate(); err != nil {
					continue
				}
				if sign.HasCertificate() {
					valuer[key] = sign.Cert.Issuer
				}
			case fields.ModuleSignatureCertSubjectSegment:
				if err := sign.ParseCertificate(); err != nil {
					continue
				}
				if sign.HasCertificate() {
					valuer[key] = sign.Cert.Subject
				}
			}
		}
	}
	return valuer
}

// sectionMapValuer returns map valuer with PE section data.
func (f *Foreach) sectionMapValuer(segments []*BoundSegmentLiteral, section pe.Sec) MapValuer {
	var valuer = MapValuer{}
	for _, seg := range segments {
		key := seg.Value
		switch seg.Segment {
		case fields.NameSegment:
			valuer[key] = section.Name
		case fields.SizeSegment:
			valuer[key] = section.Size
		case fields.EntropySegment:
			valuer[key] = section.Entropy
		case fields.MD5Segment:
			valuer[key] = section.Md5
		}
	}
	return valuer
}
