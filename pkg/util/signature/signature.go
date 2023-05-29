/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package signature

import (
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/sys"
	log "github.com/sirupsen/logrus"
	"runtime"
	"sync"
)

var isWintrustDLLFound bool
var once sync.Once

// Check determines if the provided executable image or DLL is signed.
// It first parses the PE security directory to look for the signature
// information. If the certificate is not embedded inside the PE object
// then this method will try to locate the hash in the catalog file.
func Check(filename string) *Signature {
	once.Do(func() {
		isWintrustDLLFound = sys.IsWintrustFound()
		if !isWintrustDLLFound {
			log.Warn("unable to find wintrust.dll library. This will lead to " +
				"PE objects signature verification to be skipped possibly " +
				"causing false positive samples in detection rules relying on " +
				"image signature filter fields")
		}
	})
	// check if the signature is embedded in PE
	f, err := pe.ParseFile(filename, pe.WithSecurity())
	if err != nil {
		return nil
	}
	s := &Signature{filename: filename}
	if f.IsSigned {
		s.Type = Embedded
		return s
	}
	if !isWintrustDLLFound {
		return nil
	}
	// maybe the signature is in the catalog?
	if IsCatalogSigned(filename) {
		s.Type = Catalog
	}
	return s
}

// Verify verifies the DLL or executable image signature.
// The signature is verified via Authenticode policy provider.
// Windows must verify the trust chain by following the certificates
// to a trusted root certificate.
// If the verification fails on the PE object, then the attempt to
// verify the signature in the catalog file is made. This method
// returns a bool value indicating if the signature is trusted.
func (s *Signature) Verify() bool {
	if !isWintrustDLLFound {
		return false
	}
	if verifyFileSignature(s.filename) || verifyCatalogSignature(s.filename) {
		s.Level = AuthenticodeLevel
		return true
	}
	s.Level = UnsignedLevel
	return false
}

// verifyFileSignature performs a trust verification action on the PE file
// by passing the inquiry to a trust provider that supports the action identifier.
func verifyFileSignature(filename string) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	t := sys.NewWintrustData(sys.WtdChoiceFile)
	defer t.Close()
	return t.VerifyFile(filename)
}
