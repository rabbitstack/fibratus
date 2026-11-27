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
	"time"

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/pe"
	psnap "github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
)

var processPESlot = new(byte)

type peOutcome struct {
	pe  *pe.PE
	err error
}

// processPE returns the PE metadata of the process that generated the event.
// If the PE enrichment is disabled, the metadata is loaded lazily and only the
// directories the expression refers to are parsed. The parse happens through
// the PE resolver, outside the critical section since it is slow, once per
// event for all the fields that read the PE. The process state is shared by all
// the events of the process, and other goroutines may populate the metadata, so
// the state is only read and written while holding the process lock.
func processPE(ctx *EvalCtx) (*pe.PE, error) {
	e := ctx.Evt
	r := memoized(ctx, processPESlot, e, func() peOutcome {
		var (
			p   *pe.PE
			exe string
		)
		if e.PS != nil {
			e.PS.RLock()
			p, exe = e.PS.PE, e.PS.Exe
			e.PS.RUnlock()
		}
		if e.PS != nil && exe != "" && p == nil {
			res := ctx.Resolvers.PE.Of(ctx, PEKey{Path: exe, Opts: PEOptions(ctx.peOpts)})
			if res.Err != nil {
				return peOutcome{err: res.Err}
			}
			p = res.PE
			e.PS.Lock()
			if e.PS.PE == nil {
				e.PS.PE = p
			} else {
				// someone else has set the PE metadata in the meantime
				p = e.PS.PE
			}
			e.PS.Unlock()
		}
		return peOutcome{pe: p}
	})
	return r.pe, r.err
}

// verifyPESignature builds the callback that verifies the PE signature.
func verifyPESignature(sign *signature.Signature) pe.SignatureCallback {
	return func() (bool, bool, *sys.Cert) {
		return sign.Exists(), sign.IsTrusted(), sign.Cert()
	}
}

// peOf returns the PE the field is read from. The fields that tell about the
// signature need it verified, which looks the signature up through its resolver.
func peOf(ctx *EvalCtx, f fields.Field) (*pe.PE, bool) {
	e := ctx.Evt
	// ignore System process
	if e.PID == psnap.SystemPID {
		return nil, false
	}
	p, err := processPE(ctx)
	if err != nil || p == nil {
		return nil, false
	}
	if f.IsPeSignature() && !p.IsSignatureVerified() {
		sign := ctx.Resolvers.Signature.Of(ctx, e.SignatureKey())
		if sign == nil {
			return nil, false
		}
		p.VerifySignature(verifyPESignature(sign))
	}
	return p, true
}

// peEvaluator returns the evaluator of the pe.* and ps.pe.* fields, and of the
// ps.signature.* ones, which are read from the PE as well. It returns nil if the
// field isn't one of them. The field of the pe namespace and the one of the ps
// namespace read the same value.
func peEvaluator(f Field) Evaluator {
	b := evaluatorBase(f)
	switch f.Name {
	case fields.PeEntrypoint, fields.PsPeEntrypoint:
		return &StringEvaluator{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) (string, bool) { return p.EntryPoint, true })}
	case fields.PeBaseAddress, fields.PsPeBaseAddress:
		return &StringEvaluator{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) (string, bool) { return p.ImageBase, true })}
	case fields.PeNumSections, fields.PsPeNumSections:
		return &Uint16Evaluator{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) (uint16, bool) { return p.NumberOfSections, true })}
	case fields.PeNumSymbols, fields.PsPeNumSymbols:
		return &Uint32Evaluator{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) (uint32, bool) { return p.NumberOfSymbols, true })}
	case fields.PeSymbols, fields.PsPeSymbols:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) ([]string, bool) { return p.Symbols, true })}
	case fields.PeImports, fields.PsPeImports:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) ([]string, bool) { return p.Imports, true })}
	case fields.PeImphash, fields.PsPeImphash:
		return &StringEvaluator{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) (string, bool) { return p.Imphash, true })}
	case fields.PeIsDotnet, fields.PsPeIsDotnet:
		return &BoolEvaluator{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) (bool, bool) { return p.IsDotnet, true })}
	case fields.PeAnomalies, fields.PsPeAnomalies:
		return &StringSliceEvaluator{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) ([]string, bool) { return p.Anomalies, true })}
	case fields.PeSections, fields.PsPeSections:
		return &FieldEvaluator[[]pe.Sec]{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) ([]pe.Sec, bool) { return p.Sections, true })}
	case fields.PeIsSigned, fields.PsSignatureExists:
		return &BoolEvaluator{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) (bool, bool) { return p.IsSigned(), true })}
	case fields.PeIsTrusted, fields.PsSignatureTrusted:
		return &BoolEvaluator{EvaluatorBase: b, Get: fromPE(f, func(p *pe.PE) (bool, bool) { return p.IsTrusted(), true })}

	case fields.PeCertIssuer, fields.PsSignatureIssuer:
		return &StringEvaluator{EvaluatorBase: b, Get: fromPE(f, fromCert(func(c *sys.Cert) string { return c.Issuer }))}
	case fields.PeCertSubject, fields.PsSignatureSubject:
		return &StringEvaluator{EvaluatorBase: b, Get: fromPE(f, fromCert(func(c *sys.Cert) string { return c.Subject }))}
	case fields.PeCertSerial, fields.PsSignatureSerial:
		return &StringEvaluator{EvaluatorBase: b, Get: fromPE(f, fromCert(func(c *sys.Cert) string { return c.SerialNumber }))}
	case fields.PeCertAfter, fields.PsSignatureAfter:
		return &TimeEvaluator{EvaluatorBase: b, Get: fromPE(f, fromCert(func(c *sys.Cert) time.Time { return c.NotAfter }))}
	case fields.PeCertBefore, fields.PsSignatureBefore:
		return &TimeEvaluator{EvaluatorBase: b, Get: fromPE(f, fromCert(func(c *sys.Cert) time.Time { return c.NotBefore }))}

	case fields.PeCompany, fields.PsPeCompany:
		return peResource(f, pe.Company)
	case fields.PeCopyright, fields.PsPeCopyright:
		return peResource(f, pe.LegalCopyright)
	case fields.PeDescription, fields.PsPeDescription:
		return peResource(f, pe.FileDescription)
	case fields.PeFileName, fields.PsPeFileName:
		return peResource(f, pe.OriginalFilename)
	case fields.PeFileVersion, fields.PsPeFileVersion:
		return peResource(f, pe.FileVersion)
	case fields.PeProduct, fields.PsPeProduct:
		return peResource(f, pe.ProductName)
	case fields.PeProductVersion, fields.PsPeProductVersion:
		return peResource(f, pe.ProductVersion)

	// the file flags are read from the parameters of the event, once the PE is known
	case fields.PeIsDLL:
		return peFileFlag(f, params.FileIsDLL)
	case fields.PeIsDriver:
		return peFileFlag(f, params.FileIsDriver)
	case fields.PeIsExecutable:
		return peFileFlag(f, params.FileIsExecutable)

	case fields.PeResources, fields.PsPeResources:
		return peResources(f)
	case fields.PeIsModified, fields.PsPeIsModified:
		return peModified(f)
	}
	return nil
}

// fromPE adapts the function that reads a property of the PE. The field has no
// value if the PE isn't available.
func fromPE[T any](f Field, get func(*pe.PE) (T, bool)) func(*EvalCtx) (T, bool) {
	return func(ctx *EvalCtx) (T, bool) {
		p, ok := peOf(ctx, f.Name)
		if !ok {
			var zero T
			return zero, false
		}
		return get(p)
	}
}

// fromCert adapts the function that reads a property of the signature
// certificate. The field has no value if the PE has no certificate.
func fromCert[T any](get func(*sys.Cert) T) func(*pe.PE) (T, bool) {
	return func(p *pe.PE) (T, bool) {
		if p.Cert == nil {
			var zero T
			return zero, false
		}
		return get(p.Cert), true
	}
}

// peResource reads a version resource.
func peResource(f Field, name string) Evaluator {
	return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: fromPE(f, func(p *pe.PE) (string, bool) { return p.VersionResources[name], true })}
}

func peFileFlag(f Field, name string) Evaluator {
	return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) (bool, bool) {
		if _, ok := peOf(ctx, f.Name); !ok {
			return false, false
		}
		return param(ctx.Evt, name, event.Params.GetBoolByName), true
	}}
}

// peResources reads pe.resources[name], which is a single version resource,
// and pe.resources, which is all of them.
func peResources(f Field) Evaluator {
	arg := f.Arg
	return &AnyEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) (any, bool) {
		p, ok := peOf(ctx, f.Name)
		if !ok {
			return nil, false
		}
		if arg == "" {
			resources := make([]string, 0, len(p.VersionResources))
			for k, v := range p.VersionResources {
				resources = append(resources, k+":"+v)
			}
			return resources, true
		}
		if v, ok := p.VersionResources[arg]; ok {
			return v, true
		}
		// match on version name prefix
		for k, v := range p.VersionResources {
			if strings.HasPrefix(k, arg) {
				return v, true
			}
		}
		return nil, false
	}}
}

// peModified reads the fields that tell if the PE was tampered.
// For a loaded executable, the PE on disk is parsed and compared with the
// PE fetched from the memory of the process at the base address of the image.
// For any other event, pe.is_modified is the flag stored in the PE metadata.
func peModified(f Field) Evaluator {
	return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: func(ctx *EvalCtx) (bool, bool) {
		e := ctx.Evt
		if e.PID == psnap.SystemPID {
			return false, false
		}
		p, err := processPE(ctx)
		if err != nil {
			return false, false
		}
		if e.IsLoadModule() {
			filename := e.GetParamAsString(params.ModulePath)
			isExecutable := filepath.Ext(filename) == ".exe" || e.Params.GetBoolByName(params.FileIsExecutable)
			if !isExecutable {
				return false, false
			}
			res := ctx.Resolvers.PEModified.Of(ctx, PEModifiedKey{
				Path: filename,
				PID:  e.Params.GetPid(),
				Base: e.Params.GetUint64ByName(params.ModuleBase),
				Opts: PEOptions(ctx.peOpts),
			})
			if res.Err != nil {
				return false, false
			}
			if p != nil {
				p.IsModified = res.Modified
			}
			return res.Modified, true
		}
		if p == nil || f.Name != fields.PeIsModified {
			return false, false
		}
		return p.IsModified, true
	}}
}
