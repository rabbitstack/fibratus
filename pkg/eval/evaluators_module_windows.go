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

	"github.com/rabbitstack/fibratus/pkg/compiler/fields"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
)

// moduleSignatureSlot identifies the memoized signature of the module the
// event is about.
var moduleSignatureSlot = new(byte)

// moduleSignature resolves the signature of the module that is being loaded.
// The certificate details are stored in the event parameters, since the
// certificate fields are read from them. It happens once per event, no matter
// how many fields or rules ask for it.
func moduleSignature(ctx *EvalCtx) *signature.Signature {
	e := ctx.Evt
	return memoized(ctx, moduleSignatureSlot, e, func() *signature.Signature {
		sign := ctx.Resolvers.Signature.Of(ctx, e.SignatureKey())
		if sign != nil && sign.HasCertificate() {
			cert := sign.Cert()
			e.SetParam(params.ModuleCertIssuer, params.Str(cert.Issuer))
			e.SetParam(params.ModuleCertSubject, params.Str(cert.Subject))
			e.SetParam(params.ModuleCertSerial, params.Str(cert.SerialNumber))
			e.SetParam(params.ModuleCertNotAfter, params.Timestamp(cert.NotAfter))
			e.SetParam(params.ModuleCertNotBefore, params.Timestamp(cert.NotBefore))
		}
		return sign
	})
}

// resolvesSignature reports if reading the field resolves the signature of the
// loaded module first. It does for the signature and the
// certificate fields, which is where the certificate parameters come from.
func resolvesSignature(f fields.Field) bool {
	return f.IsModuleSignature() || f == fields.ImageSignatureType || f == fields.ImageSignatureLevel || f.IsImageCert()
}

// moduleFileInfo returns the metadata of the module file for the loaded module.
func moduleFileInfo(ctx *EvalCtx) *fs.FileInfo {
	if !ctx.Evt.IsLoadModule() {
		return nil
	}
	return ctx.Resolvers.FileMeta.Of(ctx, ctx.Evt.GetParamAsString(params.ModulePath))
}

// moduleEvaluator returns the module.*, image.* and dll.* evaluator of the field,
// or nil if the field isn't one of them. The three namespaces read the same
// values, but not every field exists in all of them.
func moduleEvaluator(f Field) Evaluator {
	switch f.Name {
	case fields.ImagePath, fields.ModulePath, fields.DllPath:
		return moduleString(f, params.ModulePath)
	case fields.ImageDefaultAddress, fields.ModuleDefaultAddress:
		return moduleString(f, params.ModuleDefaultBase)
	case fields.ImageBase, fields.ModuleBase, fields.DllBase:
		return moduleString(f, params.ModuleBase)
	case fields.ImageSignatureType, fields.ModuleSignatureType, fields.DllSignatureType:
		return moduleString(f, params.ModuleSignatureType)
	case fields.ImageSignatureLevel, fields.ModuleSignatureLevel, fields.DllSignatureLevel:
		return moduleString(f, params.ModuleSignatureLevel)
	case fields.ImageCertSubject, fields.ModuleSignatureSubject, fields.DllSignatureSubject:
		return moduleString(f, params.ModuleCertSubject)
	case fields.ImageCertIssuer, fields.ModuleSignatureIssuer, fields.DllSignatureIssuer:
		return moduleString(f, params.ModuleCertIssuer)
	case fields.ImageCertSerial, fields.ModuleSignatureSerial, fields.DllSignatureSerial:
		return moduleString(f, params.ModuleCertSerial)

	case fields.ModulePathStem, fields.DllPathStem:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: moduleGet(f, always(func(e *event.Event) string {
			path := e.GetParamAsString(params.ModulePath)
			n := strings.LastIndexByte(path, '.')
			if n == -1 {
				return path
			}
			return path[:n]
		}))}
	case fields.ImageName, fields.ModuleName, fields.DllName:
		return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: moduleGet(f, always(func(e *event.Event) string {
			return filepath.Base(e.GetParamAsString(params.ModulePath))
		}))}

	case fields.ImageSize, fields.ModuleSize, fields.DllSize:
		return &Uint64Evaluator{EvaluatorBase: evaluatorBase(f), Get: moduleGet(f, fromParam(params.ModuleSize, event.Params.GetUint64ByName))}
	case fields.ImageChecksum, fields.ModuleChecksum:
		return &Uint32Evaluator{EvaluatorBase: evaluatorBase(f), Get: moduleGet(f, fromParam(params.ModuleCheckSum, event.Params.GetUint32ByName))}
	case fields.ImagePID, fields.ModulePID, fields.DllPID:
		return &Uint32Evaluator{EvaluatorBase: evaluatorBase(f), Get: moduleGet(f, fromParam(params.ProcessID, event.Params.GetUint32ByName))}
	case fields.ImageCertBefore, fields.ModuleSignatureBefore, fields.DllSignatureBefore:
		return &TimeEvaluator{EvaluatorBase: evaluatorBase(f), Get: moduleGet(f, fromParam(params.ModuleCertNotBefore, event.Params.GetTimeByName))}
	case fields.ImageCertAfter, fields.ModuleSignatureAfter, fields.DllSignatureAfter:
		return &TimeEvaluator{EvaluatorBase: evaluatorBase(f), Get: moduleGet(f, fromParam(params.ModuleCertNotAfter, event.Params.GetTimeByName))}

	// the signature verdicts are only produced for the events that load the module
	case fields.ModuleSignatureExists, fields.DllSignatureExists:
		return moduleVerdict(f, (*signature.Signature).Exists)
	case fields.ModuleSignatureTrusted, fields.DllSignatureTrusted:
		return moduleVerdict(f, (*signature.Signature).IsTrusted)

	// the file metadata is resolved for the loaded module only
	case fields.ImageIsDLL, fields.ModuleIsDLL:
		return moduleMeta(f, func(fi *fs.FileInfo) bool { return fi.IsDLL })
	case fields.ImageIsDriver, fields.ModuleIsDriver:
		return moduleMeta(f, func(fi *fs.FileInfo) bool { return fi.IsDriver })
	case fields.ImageIsExecutable, fields.ModuleIsExecutable:
		return moduleMeta(f, func(fi *fs.FileInfo) bool { return fi.IsExecutable })
	case fields.ImageIsDotnet, fields.ModuleIsDotnet, fields.DllIsDotnet:
		return moduleMeta(f, func(fi *fs.FileInfo) bool { return fi.IsDotnet })
	}
	return nil
}

// moduleString reads the event parameter in its string form.
func moduleString(f Field, name string) Evaluator {
	return &StringEvaluator{EvaluatorBase: evaluatorBase(f), Get: moduleGet(f, always(func(e *event.Event) string { return e.GetParamAsString(name) }))}
}

func moduleVerdict(f Field, get func(*signature.Signature) bool) Evaluator {
	return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: moduleGet(f, func(ctx *EvalCtx) (bool, bool) {
		if !ctx.Evt.IsLoadModule() {
			return false, false
		}
		sign := moduleSignature(ctx)
		return sign != nil && get(sign), true
	})}
}

func moduleMeta(f Field, get func(*fs.FileInfo) bool) Evaluator {
	return &BoolEvaluator{EvaluatorBase: evaluatorBase(f), Get: moduleGet(f, func(ctx *EvalCtx) (bool, bool) {
		file := moduleFileInfo(ctx)
		return file != nil && get(file), true
	})}
}

// moduleGet makes the function resolve the signature of the loaded module
// before it reads the field, if the field is one of the signature or the
// certificate fields, which is where the certificate parameters come from.
func moduleGet[T any](f Field, get func(*EvalCtx) (T, bool)) func(*EvalCtx) (T, bool) {
	if !resolvesSignature(f.Name) {
		return get
	}
	return func(ctx *EvalCtx) (T, bool) {
		if ctx.Evt.IsLoadModule() {
			moduleSignature(ctx)
		}
		return get(ctx)
	}
}
