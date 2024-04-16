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
	"time"
)

// Signatures manages and caches DLL and executable signatures.
type Signatures struct {
	signatures map[uint64]*Signature
	mux        sync.Mutex
	purger     *time.Ticker
}

var sigs *Signatures

// sigTTL maximum time for the signature to remain in the
// internal store before it is purged.
var sigTTL = 10 * time.Minute

// GetSignatures creates a new signatures singleton.
func GetSignatures() *Signatures {
	if sigs != nil {
		return sigs
	}
	sigs = &Signatures{
		signatures: make(map[uint64]*Signature),
		purger:     time.NewTicker(time.Minute),
	}

	go sigs.gcSignatures()

	return sigs
}

// GetSignature retrieves the signature by base address. If
// the signature exists, its accessed timestamp is updated
// to prevent it being purged by the gc.
func (s *Signatures) GetSignature(addr uint64) *Signature {
	s.mux.Lock()
	defer s.mux.Unlock()
	sign, ok := s.signatures[addr]
	if !ok {
		return nil
	}
	sign.keepalive()
	return sign
}

// PutSignature links the signature data to the specified base address.
func (s *Signatures) PutSignature(addr uint64, sign *Signature) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.signatures[addr] == nil {
		s.signatures[addr] = sign
	}
}

func (s *Signatures) gcSignatures() {
	for {
		<-s.purger.C
		s.mux.Lock()
		for addr, sig := range s.signatures {
			if time.Since(sig.accessed) > sigTTL {
				log.Debugf("removing signature info for file %s", sig.Filename)
				delete(s.signatures, addr)
			}
		}
		s.mux.Unlock()
	}
}

// ParseCertificate parses the certificate data for catalog-based
// signatures.
func (s *Signature) ParseCertificate() error {
	// the certificate exists in the PE security directory
	if s.Cert != nil {
		return nil
	}
	if !sys.IsWintrustFound() {
		return ErrWintrustUnavailable
	}
	// parse catalog certificate
	catalog := sys.NewCatalog()
	if err := catalog.Open(s.Filename); err != nil {
		return err
	}
	defer catalog.Close()
	var err error
	s.Cert, err = catalog.ParseCertificate()
	if err != nil {
		return err
	}
	return nil
}

// Check determines if the provided executable image or DLL is signed.
// It first parses the PE security directory to look for the signature
// information. If the certificate is not embedded inside the PE object
// then this method will try to locate the hash in the catalog file. If
// the certificate parsing is successful, this function returns the
// signature structure containing the signature type and certificate info.
// If the signature is not present, this function returns ErrNotSigned error.
// To verify the signature, call the Verify method of the Signature structure.
// On success, this method returns the signature type and the signature level.
// The signature level is either unchecked or unsigned. It is necessary to
// call the Verify method to determine the signature chain trust.
func (s *Signature) Check() (uint32, uint32, error) {
	// check if the signature is embedded in PE
	f, err := pe.ParseFile(s.Filename, pe.WithSecurity())
	if err != nil {
		return None, UncheckedLevel, err
	}
	if f.IsSigned {
		s.Cert = f.Cert
		return Embedded, UncheckedLevel, nil
	}

	if !sys.IsWintrustFound() {
		return None, UncheckedLevel, ErrWintrustUnavailable
	}

	// maybe the signature is in the catalog?
	catalog := sys.NewCatalog()
	if err := catalog.Open(s.Filename); err != nil {
		return None, UncheckedLevel, err
	}
	defer catalog.Close()
	if catalog.IsCatalogSigned() {
		return Catalog, UncheckedLevel, nil
	}
	return None, UnsignedLevel, ErrNotSigned // image not signed
}

// Verify verifies the DLL or executable image signature.
// The signature is verified via Authenticode policy provider.
// Windows must verify the trust chain by following the certificates
// to a trusted root certificate.
// If the verification fails on the PE object, then the attempt to
// verify the signature in the catalog file is made. This method
// returns a bool value indicating if the signature is trusted.
func (s *Signature) Verify() bool {
	if !sys.IsWintrustFound() {
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
