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
	"sync"
)

var isWintrustDLLFound bool
var once sync.Once

// Wrap returns a new signature form signature type and level.
func Wrap(typ, level uint32) *Signature {
	return &Signature{Type: typ, Level: level}
}

// GetCertificate returns certificate details for the specific PE object.
func GetCertificate(filename string) (*pe.Cert, error) {
	onceWintrustDLL()
	f, err := pe.ParseFile(filename, pe.WithSecurity())
	if err != nil {
		return nil, err
	}
	if f.Cert != nil {
		return f.Cert, nil
	}
	if !isWintrustDLLFound {
		return nil, ErrWintrustUnavailable
	}
	// parse catalog certificate
	catalog := NewCatalog()
	if err := catalog.Open(filename); err != nil {
		return nil, err
	}
	defer catalog.Close()
	cert, err := catalog.ParseCertificate()
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// Check determines if the provided executable image or DLL is signed.
// It first parses the PE security directory to look for the signature
// information. If the certificate is not embedded inside the PE object
// then this method will try to locate the hash in the catalog file. If
// the certificate parsing is successful, this function returns the signature
// structure containing the signature type and certificate info. If the signature
// is not present, this function returns ErrNotSigned error. To verify the signature,
// call the Verify method of the Signature structure.
func Check(filename string) (*Signature, error) {
	onceWintrustDLL()
	// check if the signature is embedded in PE
	f, err := pe.ParseFile(filename, pe.WithSecurity())
	if err != nil {
		return nil, err
	}
	if f.IsSigned {
		return &Signature{filename: filename, Type: Embedded, Cert: f.Cert}, nil
	}

	if !isWintrustDLLFound {
		return nil, ErrWintrustUnavailable
	}

	// maybe the signature is in the catalog?
	catalog := NewCatalog()
	if err := catalog.Open(filename); err != nil {
		return nil, err
	}
	defer catalog.Close()
	if catalog.IsCatalogSigned() {
		cert, err := catalog.ParseCertificate()
		if err != nil {
			return nil, err
		}
		return &Signature{filename: filename, Type: Catalog, Cert: cert}, nil
	}
	return nil, ErrNotSigned // image not signed
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
	s.Level = UnsignedLevel
	isTrusted := s.VerifyEmbedded() || s.VerifyCatalog()
	if isTrusted {
		s.Level = AuthenticodeLevel
		return isTrusted
	}
	return false
}

func onceWintrustDLL() {
	once.Do(func() {
		isWintrustDLLFound = sys.IsWintrustFound()
		if !isWintrustDLLFound {
			log.Warn("unable to find wintrust.dll library. This will lead to " +
				"PE objects signature verification to be skipped possibly " +
				"causing false positive samples in detection rules relying on " +
				"image signature filter fields")
		}
	})
}
