/*
 * Copyright 2021-present by Nedim Sabic Sabic
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

package filter

import (
	"path/filepath"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/util/loldrivers"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// isLOLDriver interacts with the loldrivers client to determine
// whether the loaded/dropped driver is malicious or vulnerable.
func isLOLDriver(f fields.Field, e *event.Event) (params.Value, error) {
	var filename string

	if e.Category == event.File {
		filename = e.GetParamAsString(params.FilePath)
	} else {
		filename = e.GetParamAsString(params.ImagePath)
	}

	isDriver := filepath.Ext(filename) == ".sys" || e.Params.TryGetBool(params.FileIsDriver)
	if !isDriver {
		return nil, nil
	}
	ok, driver := loldrivers.GetClient().MatchHash(filename)
	if !ok {
		return nil, nil
	}
	if (f == fields.FileIsDriverVulnerable || f == fields.ImageIsDriverVulnerable) && driver.IsVulnerable {
		return true, nil
	}
	if (f == fields.FileIsDriverMalicious || f == fields.ImageIsDriverMalicious) && driver.IsMalicious {
		return true, nil
	}
	return false, nil
}

// initLOLDriversClient initializes the loldrivers client if the filter expression
// contains any of the relevant fields.
func initLOLDriversClient(flds []Field) {
	for _, f := range flds {
		if f.Name == fields.FileIsDriverVulnerable || f.Name == fields.FileIsDriverMalicious ||
			f.Name == fields.ImageIsDriverVulnerable || f.Name == fields.ImageIsDriverMalicious {
			loldrivers.InitClient(loldrivers.WithAsyncDownload())
		}
	}
}

// getSignature tries to find the module signature mapped to the given address.
// If the signature is not found in the cache, then a fresh signature instance
// is created and verified.
func getSignature(addr va.Address, filename string, parseCert bool) *signature.Signature {
	sign := signature.GetSignatures().GetSignature(addr.Uint64())
	if sign != nil {
		if parseCert {
			err := sign.ParseCertificate()
			if err != nil {
				certErrors.Add(1)
			}
		}
		return sign
	}

	var err error
	sign = &signature.Signature{Filename: filename}
	sign.Type, sign.Level, err = sign.Check()
	if err != nil {
		signatureErrors.Add(1)
	}

	if sign.IsSigned() {
		sign.Verify()
	}

	if parseCert {
		err = sign.ParseCertificate()
		if err != nil {
			certErrors.Add(1)
		}
	}

	signature.GetSignatures().PutSignature(addr.Uint64(), sign)

	return sign
}

// framePID returns the pid associated with the stack frame.
func framePID(e *event.Event) uint32 {
	if !e.Callstack.IsEmpty() && e.Callstack.FrameAt(0).PID != 0 {
		return e.Callstack.FrameAt(0).PID
	}
	return e.PID
}
