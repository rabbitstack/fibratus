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

type opts struct {
	onlyCert bool
}

// Option represents the option that influences signature verification/checking process
type Option func(o *opts)

// OnlyCert indicates if only certificate info is fetched for the signature. If this
// option is set, it is assumed the signature was already checked.
func OnlyCert() Option {
	return func(o *opts) {
		o.onlyCert = true
	}
}

// CheckWithOpts determines if the provided executable image or DLL is signed.
// It first parses the PE security directory to look for the signature
// information. If the certificate is not embedded inside the PE object
// then this method will try to locate the hash in the catalog file.
// If OnlyCert option is specified, then only certificate information is
// fetched for the particular executable image, DLL, or driver. If the function
// returns a nil value, this indicates the provided image is not signed.
func CheckWithOpts(filename string, options ...Option) (*Signature, error) {
	once.Do(func() {
		isWintrustDLLFound = sys.IsWintrustFound()
		if !isWintrustDLLFound {
			log.Warn("unable to find wintrust.dll library. This will lead to " +
				"PE objects signature verification to be skipped possibly " +
				"causing false positive samples in detection rules relying on " +
				"image signature filter fields")
		}
	})
	var opts opts
	for _, opt := range options {
		opt(&opts)
	}
	// the signature is assumed to be verified, so we just extract cert info
	if opts.onlyCert {
		f, err := pe.ParseFile(filename, pe.WithSecurity())
		if err != nil {
			return nil, err
		}
		if f.Cert != nil {
			return &Signature{filename: filename, Cert: f.Cert}, nil
		}
		if !isWintrustDLLFound {
			return nil, ErrWintrustUnavailable
		}
		// parse catalog certificate
		catalog := NewCatalog()
		if err := catalog.Open(filename); err != nil {
			return nil, err
		}
		cert, err := catalog.ParseCertificate()
		if err != nil {
			return nil, err
		}
		return &Signature{filename: filename, Cert: cert}, nil
	}

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
	if s.VerifyEmbedded() || s.VerifyCatalog() {
		s.Level = AuthenticodeLevel
		return true
	}
	return false
}
