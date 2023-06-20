/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package processors

import (
	"expvar"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
)

// signatureErrors counts signature check/verification errors
var signatureErrors = expvar.NewInt("image.signature.errors")

type imageProcessor struct {
	psnap      ps.Snapshotter
	signatures map[uint32]*signature.Signature
}

func newImageProcessor(psnap ps.Snapshotter) Processor {
	return &imageProcessor{psnap: psnap, signatures: make(map[uint32]*signature.Signature)}
}

func (imageProcessor) Name() ProcessorType { return Image }

func (m *imageProcessor) ProcessEvent(e *kevent.Kevent) (*kevent.Kevent, bool, error) {
	if e.IsLoadImage() {
		// image signature parameters exhibit unreliable behaviour. Allegedly,
		// signature verification is not performed in certain circumstances
		// which leads to the core system DLL or binaries to be reported with
		// signature unchecked level.
		// To mitigate this situation, we have to manually check/verify the signature
		// for all unchecked signature levels. Additionally, when possible, the events
		// are augmented with signature certificate parameters
		err := m.processSignature(e)
		if err != nil {
			signatureErrors.Add(1)
		}
	}
	if e.IsUnloadImage() {
		pid := e.Kparams.MustGetPid()
		mod := e.GetParamAsString(kparams.ImageFilename)
		if pid == 0 {
			pid = e.PID
		}
		// reset signature parameters from process state
		proc := m.psnap.FindAndPut(pid)
		if proc != nil {
			module := proc.FindModule(mod)
			if module != nil {
				_ = e.Kparams.SetValue(kparams.ImageSignatureType, module.SignatureType)
				_ = e.Kparams.SetValue(kparams.ImageSignatureLevel, module.SignatureLevel)
			}
		}
		return e, false, m.psnap.RemoveModule(pid, mod)
	}
	if e.IsLoadImage() {
		return e, false, m.psnap.AddModule(e)
	}
	return e, true, nil
}

func (imageProcessor) Close() {}

// processSignature consults the signature cache and if the signature
// already exists for a particular image checksum, signature checking
// is skipped. On the contrary, the signature verification is performed
// and the cache is updated accordingly.
func (m *imageProcessor) processSignature(e *kevent.Kevent) error {
	checksum := e.Kparams.MustGetUint32(kparams.ImageCheckSum)
	level := e.Kparams.MustGetUint32(kparams.ImageSignatureLevel)
	sign, ok := m.signatures[checksum]
	if !ok {
		var opts []signature.Option
		var filename = e.GetParamAsString(kparams.FileName)
		if level != signature.UncheckedLevel {
			opts = append(opts, signature.OnlyCert())
		}
		var err error
		sign, err = signature.CheckWithOpts(filename, opts...)
		if err != nil {
			return err
		}
		if level == signature.UncheckedLevel && sign.IsSigned() {
			sign.Verify()
		}
		m.signatures[checksum] = sign
	}
	if level == signature.UncheckedLevel {
		// reset signature type/level parameters
		_ = e.Kparams.SetValue(kparams.ImageSignatureType, sign.Type)
		_ = e.Kparams.SetValue(kparams.ImageSignatureLevel, sign.Level)
	}
	// append certificate parameters
	if sign.HasCertificate() {
		e.AppendParam(kparams.ImageCertIssuer, kparams.UnicodeString, sign.Cert.Issuer)
		e.AppendParam(kparams.ImageCertSubject, kparams.UnicodeString, sign.Cert.Subject)
		e.AppendParam(kparams.ImageCertSerial, kparams.UnicodeString, sign.Cert.SerialNumber)
		e.AppendParam(kparams.ImageCertNotAfter, kparams.Time, sign.Cert.NotAfter)
		e.AppendParam(kparams.ImageCertNotBefore, kparams.Time, sign.Cert.NotBefore)
	}
	return nil
}
