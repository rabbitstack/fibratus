//go:build windows

/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
 * Copyright 2026 by Mostafa Moradian
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
	"path/filepath"

	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/filter/ql/functions"
	"github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"golang.org/x/sys/windows"
)

func init() {
	funcs[functions.IsMinidumpFn.String()] = &functions.IsMinidump{}
	funcs[functions.GetRegValueFn.String()] = &functions.GetRegValue{}
}

func (f *Foreach) foreachPlatform(elems interface{}, segments []*BoundSegmentLiteral, e interface{}, useCallValuer bool, valuer MapValuer) (bool, bool) {
	switch elems := elems.(type) {
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
	case []pe.Sec:
		for _, sec := range elems {
			if f.evalExpr(e, useCallValuer, f.sectionMapValuer(segments, sec), valuer) {
				return true, true
			}
		}
	}
	return false, false
}

func addPlatformProcessValues(segments []*BoundSegmentLiteral, proc *pstypes.PS, valuer MapValuer) {
	for _, seg := range segments {
		switch seg.Segment {
		case fields.SIDSegment:
			valuer[seg.Value] = proc.SID
		case fields.SessionIDSegment:
			valuer[seg.Value] = proc.SessionID
		case fields.DomainSegment:
			valuer[seg.Value] = proc.Domain
		case fields.TokenIntegrityLevelSegment:
			valuer[seg.Value] = proc.TokenIntegrityLevel
		case fields.TokenIsElevatedSegment:
			valuer[seg.Value] = proc.IsTokenElevated
		case fields.TokenElevationTypeSegment:
			valuer[seg.Value] = proc.TokenElevationType
		}
	}
}

// moduleMapValuer returns the map valuer with process module attributes.
func (f *Foreach) moduleMapValuer(segments []*BoundSegmentLiteral, mod pstypes.Module) MapValuer {
	valuer := MapValuer{}
	for _, seg := range segments {
		switch seg.Segment {
		case fields.PathSegment:
			valuer[seg.Value] = mod.Name
		case fields.NameSegment:
			valuer[seg.Value] = filepath.Base(mod.Name)
		case fields.AddressSegment:
			valuer[seg.Value] = mod.BaseAddress.String()
		case fields.SizeSegment:
			valuer[seg.Value] = mod.Size
		case fields.ChecksumSegment:
			valuer[seg.Value] = mod.Checksum
		}
	}
	return valuer
}

// threadMapValuer returns the map valuer with thread information.
func (f *Foreach) threadMapValuer(segments []*BoundSegmentLiteral, thread pstypes.Thread) MapValuer {
	valuer := MapValuer{}
	for _, seg := range segments {
		switch seg.Segment {
		case fields.TidSegment:
			valuer[seg.Value] = thread.Tid
		case fields.StartAddressSegment:
			valuer[seg.Value] = thread.StartAddress.String()
		case fields.UserStackBaseSegment:
			valuer[seg.Value] = thread.UstackBase.String()
		case fields.UserStackLimitSegment:
			valuer[seg.Value] = thread.UstackLimit.String()
		case fields.KernelStackBaseSegment:
			valuer[seg.Value] = thread.KstackBase.String()
		case fields.KernelStackLimitSegment:
			valuer[seg.Value] = thread.KstackLimit.String()
		}
	}
	return valuer
}

// sectionMapValuer returns map valuer with PE section data.
func (f *Foreach) sectionMapValuer(segments []*BoundSegmentLiteral, section pe.Sec) MapValuer {
	valuer := MapValuer{}
	for _, seg := range segments {
		switch seg.Segment {
		case fields.NameSegment:
			valuer[seg.Value] = section.Name
		case fields.SizeSegment:
			valuer[seg.Value] = section.Size
		case fields.EntropySegment:
			valuer[seg.Value] = section.Entropy
		case fields.MD5Segment:
			valuer[seg.Value] = section.Md5
		}
	}
	return valuer
}

// foreachCallstack evaluates the predicate against callstack frames.
// The first return value indicates whether callstack handling applied;
// the second is the match result.
func (f *Foreach) foreachCallstack(elems callstack.Callstack, segments []*BoundSegmentLiteral, e interface{}, useCallValuer bool, valuer MapValuer) (bool, bool) {
	var pid uint32
	var proc windows.Handle
	var err error

	if !elems.IsEmpty() {
		pid = elems.FrameAt(0).PID
	}

	var desiredAccess uint32
loop:
	for _, seg := range segments {
		switch seg.Segment {
		case fields.CallsiteLeadingAssemblySegment, fields.CallsiteTrailingAssemblySegment:
			desiredAccess = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
			break loop
		case fields.AllocationSizeSegment, fields.ProtectionSegment:
			desiredAccess = windows.PROCESS_QUERY_INFORMATION
		}
	}
	if desiredAccess != 0 {
		proc, err = windows.OpenProcess(desiredAccess, false, pid)
		if err != nil {
			return true, false
		}
		defer windows.Close(proc)
	}

	for _, frame := range elems {
		if f.evalExpr(e, useCallValuer, f.callstackMapValuer(segments, frame, proc), valuer) {
			return true, true
		}
	}
	return true, false
}

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
		case fields.ModuleSignatureExistsSegment, fields.ModuleSignatureTrustedSegment,
			fields.ModuleSignatureIssuerSegment, fields.ModuleSignatureSubjectSegment:

			sign := signature.GetSignatures().DoRequest(signature.MakeKey(frame.Module, 0, 0, 0))
			if sign == nil {
				continue
			}

			switch seg.Segment {
			case fields.ModuleSignatureExistsSegment:
				valuer[key] = sign.Exists()
			case fields.ModuleSignatureTrustedSegment:
				valuer[key] = sign.IsTrusted()
			case fields.ModuleSignatureIssuerSegment:
				if sign.HasCertificate() {
					valuer[key] = sign.Cert().Issuer
				}
			case fields.ModuleSignatureSubjectSegment:
				if sign.HasCertificate() {
					valuer[key] = sign.Cert().Subject
				}
			}
		}
	}
	return valuer
}
