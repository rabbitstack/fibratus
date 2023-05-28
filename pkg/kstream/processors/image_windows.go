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
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
)

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
		// for all unchecked signature levels
		level := e.Kparams.MustGetUint32(kparams.ImageSignatureLevel)
		if level == signature.UncheckedLevel {
			m.checkSignature(e)
		}
	}
	if e.IsUnloadImage() {
		return e, false, m.psnap.RemoveModule(e.Kparams.MustGetPid(), e.GetParamAsString(kparams.ImageFilename))
	}
	if e.IsLoadImage() {
		return e, false, m.psnap.AddModule(e)
	}
	return e, true, nil
}

func (imageProcessor) Close() {}

// checkSignature consults the signature cache and if the signature
// already exists for a particular image checksum, signature checking
// is skipped. On the contrary, the signature verification is performed
// and the cache is updated accordingly.
func (m *imageProcessor) checkSignature(e *kevent.Kevent) {
	checksum := e.Kparams.MustGetUint32(kparams.ImageCheckSum)
	sign, ok := m.signatures[checksum]
	if !ok {
		filename := e.GetParamAsString(kparams.FileName)
		sign = signature.Check(filename)
		if sign == nil {
			return
		}
		if sign.IsSigned() {
			sign.Verify()
		}
		m.signatures[checksum] = sign
	}
	if sign != nil {
		_ = e.Kparams.SetValue(kparams.ImageSignatureType, sign.Type)
		_ = e.Kparams.SetValue(kparams.ImageSignatureLevel, sign.Level)
	}
}
