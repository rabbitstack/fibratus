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
	"maps"
	"path/filepath"
	"slices"

	"github.com/rabbitstack/fibratus/pkg/callstack"
	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/pe"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"golang.org/x/sys/windows"
)

// eachPlatform iterates over the collections that exist on Windows only.
func (e *ForeachEvaluator) eachPlatform(ctx *EvalCtx, collection any) any {
	switch items := collection.(type) {
	case []pstypes.Module:
		return loop(e, ctx, slices.Values(items), bindModule)
	case map[uint32]pstypes.Thread:
		return loop(e, ctx, maps.Values(items), bindThread)
	case []pe.Sec:
		return loop(e, ctx, slices.Values(items), bindSection)
	case callstack.Callstack:
		return e.eachFrame(ctx, items)
	}
	return false
}

func bindPlatformProcess(b *binding, proc *pstypes.PS) {
	for _, seg := range b.segments {
		switch seg.Segment {
		case fields.SIDSegment:
			b.values[seg.Value] = proc.SID
		case fields.SessionIDSegment:
			b.values[seg.Value] = proc.SessionID
		case fields.DomainSegment:
			b.values[seg.Value] = proc.Domain
		case fields.TokenIntegrityLevelSegment:
			b.values[seg.Value] = proc.TokenIntegrityLevel
		case fields.TokenIsElevatedSegment:
			b.values[seg.Value] = proc.IsTokenElevated
		case fields.TokenElevationTypeSegment:
			b.values[seg.Value] = proc.TokenElevationType
		}
	}
}

// bindModule exposes the process module attributes.
func bindModule(b *binding, mod pstypes.Module) {
	for _, seg := range b.segments {
		switch seg.Segment {
		case fields.PathSegment:
			b.values[seg.Value] = mod.Name
		case fields.NameSegment:
			b.values[seg.Value] = filepath.Base(mod.Name)
		case fields.AddressSegment:
			b.values[seg.Value] = mod.BaseAddress.String()
		case fields.SizeSegment:
			b.values[seg.Value] = mod.Size
		case fields.ChecksumSegment:
			b.values[seg.Value] = mod.Checksum
		}
	}
}

// bindThread exposes the thread information.
func bindThread(b *binding, thread pstypes.Thread) {
	for _, seg := range b.segments {
		switch seg.Segment {
		case fields.TidSegment:
			b.values[seg.Value] = thread.Tid
		case fields.StartAddressSegment:
			b.values[seg.Value] = thread.StartAddress.String()
		case fields.UserStackBaseSegment:
			b.values[seg.Value] = thread.UstackBase.String()
		case fields.UserStackLimitSegment:
			b.values[seg.Value] = thread.UstackLimit.String()
		case fields.KernelStackBaseSegment:
			b.values[seg.Value] = thread.KstackBase.String()
		case fields.KernelStackLimitSegment:
			b.values[seg.Value] = thread.KstackLimit.String()
		}
	}
}

// bindSection exposes the PE section data.
func bindSection(b *binding, section pe.Sec) {
	for _, seg := range b.segments {
		switch seg.Segment {
		case fields.NameSegment:
			b.values[seg.Value] = section.Name
		case fields.SizeSegment:
			b.values[seg.Value] = section.Size
		case fields.EntropySegment:
			b.values[seg.Value] = section.Entropy
		case fields.MD5Segment:
			b.values[seg.Value] = section.Md5
		}
	}
}

// eachFrame evaluates the predicate for the frames of the callstack. The
// attributes that are read from the memory of the process, e.g. the allocation
// size or the assembly of the callsite, need the process opened, and the
// predicate doesn't hold if the process can't be.
func (e *ForeachEvaluator) eachFrame(ctx *EvalCtx, frames callstack.Callstack) bool {
	var pid uint32
	if !frames.IsEmpty() {
		pid = frames.FrameAt(0).PID
	}

	var desiredAccess uint32
loop:
	for _, seg := range e.Segments {
		switch seg.Segment {
		case fields.CallsiteLeadingAssemblySegment, fields.CallsiteTrailingAssemblySegment:
			desiredAccess = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
			break loop
		case fields.AllocationSizeSegment, fields.ProtectionSegment:
			desiredAccess = windows.PROCESS_QUERY_INFORMATION
		}
	}
	var proc windows.Handle
	if desiredAccess != 0 {
		var err error
		proc, err = windows.OpenProcess(desiredAccess, false, pid)
		if err != nil {
			return false
		}
		defer windows.Close(proc)
	}

	return loopFrames(e, ctx, frames, func(b *binding, frame callstack.Frame) {
		bindFrame(b, frame, proc)
	})
}

func loopFrames(e *ForeachEvaluator, ctx *EvalCtx, frames callstack.Callstack, bind func(*binding, callstack.Frame)) bool {
	return loop(e, ctx, slices.Values(frames), bind)
}

// bindFrame exposes the attributes of the stack frame.
func bindFrame(b *binding, frame callstack.Frame, proc windows.Handle) {
	for _, seg := range b.segments {
		key := seg.Value
		switch seg.Segment {
		case fields.AddressSegment:
			b.values[key] = frame.Addr.String()
		case fields.OffsetSegment:
			b.values[key] = frame.Offset
		case fields.IsUnbackedSegment:
			b.values[key] = frame.IsUnbacked()
		case fields.ModuleSegment:
			b.values[key] = frame.Module
		case fields.SymbolSegment:
			b.values[key] = frame.Module + "!" + frame.Symbol
		case fields.AllocationSizeSegment:
			b.values[key] = frame.AllocationSize(proc)
		case fields.ProtectionSegment:
			b.values[key] = frame.Protection(proc)
		case fields.CallsiteTrailingAssemblySegment:
			b.values[key] = frame.CallsiteAssembly(proc, false)
		case fields.CallsiteLeadingAssemblySegment:
			b.values[key] = frame.CallsiteAssembly(proc, true)
		case fields.ModuleSignatureExistsSegment, fields.ModuleSignatureTrustedSegment,
			fields.ModuleSignatureIssuerSegment, fields.ModuleSignatureSubjectSegment:

			sign := signature.GetSignatures().DoRequest(signature.MakeKey(frame.Module, 0, 0, 0))
			if sign == nil {
				continue
			}

			switch seg.Segment {
			case fields.ModuleSignatureExistsSegment:
				b.values[key] = sign.Exists()
			case fields.ModuleSignatureTrustedSegment:
				b.values[key] = sign.IsTrusted()
			case fields.ModuleSignatureIssuerSegment:
				if sign.HasCertificate() {
					b.values[key] = sign.Cert().Issuer
				}
			case fields.ModuleSignatureSubjectSegment:
				if sign.HasCertificate() {
					b.values[key] = sign.Cert().Subject
				}
			}
		}
	}
}
