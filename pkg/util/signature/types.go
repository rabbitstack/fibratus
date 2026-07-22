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

package signature

import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/sys"
)

// Type defines the signature verification type.
type Type uint32

const (
	TypeNone            Type = 0 // unsigned or verification hasn't been attempted
	TypeEmbedded        Type = 1 // embedded signature
	TypeCached          Type = 2 // cached signature; presence of a CI EA means the file was previously verified
	TypeCatalogCached   Type = 3 // cached catalog verified via Catalog Database or searching catalog directly
	TypeCatalogUncached Type = 4 // uncached catalog verified via Catalog Database or searching catalog directly
	TypeCatalogHint     Type = 5 // successfully verified using an EA that informs CI that catalog to try first
	TypePackageCatalog  Type = 6 // AppX / MSIX package catalog verified
	TypeFileVerified    Type = 7 // the file was verified
)

func (t Type) String() string {
	switch t {
	case TypeNone:
		return "None"
	case TypeEmbedded:
		return "Embedded"
	case TypeCached:
		return "Cached"
	case TypeCatalogCached:
		return "CatalogCached"
	case TypeCatalogUncached:
		return "CatalogUncached"
	case TypeCatalogHint:
		return "CatalogHint"
	case TypePackageCatalog:
		return "PackageCatalog"
	case TypeFileVerified:
		return "FileVerified"
	default:
		return fmt.Sprintf("%d", uint32(t))
	}
}

// Level defines the image signing level.
type Level uint32

const (
	LevelUnchecked      Level = 0 // signing level hasn't yet been checked
	LevelUnsigned       Level = 1 // file is unsigned or has no signature that passes the active policies
	LevelEnterprise     Level = 2 // trusted by Windows Defender Application Control policy
	LevelDeveloper      Level = 3 // developer signed code
	LevelAuthenticode   Level = 4 // Authenticode signed
	LevelStorePPL       Level = 5 // Microsoft Store signed app PPL (Protected Process Light)
	LevelStore          Level = 6 // Microsoft Store-signed
	LevelAntimalware    Level = 7 // signed by an Antimalware vendor whose product is using AMPPL
	LevelMicrosoft      Level = 8 // Microsoft signed
	LevelCustom4        Level = 9
	LevelCustom5        Level = 10
	LevelDynamicCodeGen Level = 11 // only used for signing of the .NET NGEN compiler
	LevelWindows        Level = 12 // Windows signed
	LevelCustom7        Level = 13
	LevelWindowsTCB     Level = 14 // Windows Trusted Computing Base signed
	LevelCustom6        Level = 15
)

var Types = map[uint32]string{
	uint32(TypeNone):            "NONE",
	uint32(TypeEmbedded):        "EMBEDDED",
	uint32(TypeCached):          "CACHED",
	uint32(TypeCatalogCached):   "CATALOG_CACHED",
	uint32(TypeCatalogUncached): "CATALOG_UNCACHED",
	uint32(TypeCatalogHint):     "CATALOG_HINT",
	uint32(TypePackageCatalog):  "PACKAGE_CATALOG",
	uint32(TypeFileVerified):    "FILE_VERIFIED",
}

var Levels = map[uint32]string{
	uint32(LevelUnchecked):      "UNCHECKED",
	uint32(LevelUnsigned):       "UNSIGNED",
	uint32(LevelEnterprise):     "ENTERPRISE",
	uint32(LevelDeveloper):      "DEVELOPER",
	uint32(LevelAuthenticode):   "AUTHENTICODE",
	uint32(LevelStorePPL):       "STORE_PPL",
	uint32(LevelStore):          "STORE",
	uint32(LevelAntimalware):    "ANTIMALWARE",
	uint32(LevelMicrosoft):      "MICROSOFT",
	uint32(LevelCustom4):        "CUSTOM_4",
	uint32(LevelCustom5):        "CUSTOM_5",
	uint32(LevelDynamicCodeGen): "DYNAMIC_CODEGEN",
	uint32(LevelWindows):        "WINDOWS",
	uint32(LevelCustom7):        "CUSTOM_7",
	uint32(LevelWindowsTCB):     "WINDOWS_TCB",
	uint32(LevelCustom6):        "CUSTOM_6",
}

// ErrNoSignature represents the error which is raised when the executable image lacks the signature
var ErrNoSignature = errors.New("image is not signed")

// ErrNilSignature represents the error that is signaled when the operation is attempted on a nil signature
var ErrNilSignature = errors.New("the signature is not initialized")

// ErrWintrustUnavailable represents the error which is raised when wintrust platform is not available
var ErrWintrustUnavailable = errors.New("wintrust is not available")

// Signature represents the signature state.
type Signature struct {
	// Path represents the name of the executable/DLL.
	Path string

	// typ indicates the signature type.
	typ atomic.Uint32

	// exists indicates if the signature exists in the PE security directory
	// or a system-wide catalog.
	exists atomic.Bool

	// status represents the signature trust status.
	status atomic.Uint32

	// cert represents certificate information for the particular signature.
	cert atomic.Pointer[sys.Cert]

	// accessed the timestamp of the signature access by field extractor.
	accessed atomic.Int64
}

func (s *Signature) String() string {
	var cert string
	if s.HasCertificate() {
		c := s.Cert()
		cert = c.Issuer + " | " + c.Subject
	}

	var accessed string
	if ts := s.accessed.Load(); ts != 0 {
		accessed = time.Unix(0, ts).Format(time.RFC3339Nano)
	}

	return fmt.Sprintf(
		"Exists: %t, Type: %s, Status: %s, Path: %s, Cert: %s, Accessed: %s}",
		s.Exists(),
		s.Type(),
		s.Status(),
		s.Path,
		cert,
		accessed,
	)
}

// IsTrusted returns true if Code Integrity successfully validates the file's trust chain.
func IsTrusted(sigType Type, sigLevel Level) bool {
	return (sigType == TypeEmbedded &&
		(sigLevel == LevelWindows || sigLevel == LevelWindowsTCB)) ||
		(sigType == TypeFileVerified && sigLevel == LevelWindows)
}

// newSignature returns a signature initialized with file name and signature type.
// If the signature type is known upfront, then we can skip the signature
// check phase to save system resources.
func newSignature(path string, sigType Type, sigLevel Level) *Signature {
	s := &Signature{
		Path: path,
	}
	s.keepalive()
	s.setType(sigType)
	s.setStatus(sys.SignatureNotTrusted)

	s.exists.Store(false)

	if IsTrusted(sigType, sigLevel) {
		s.setExists()
		s.setStatus(sys.SignatureTrusted)
	}

	return s
}

// newUncheckedSignature creates a new signature with none type and unchecked signature level.
// This is the default constructor for any non-trusted signature verification.
func newUncheckedSignature(path string) *Signature {
	return newSignature(path, TypeNone, LevelUnchecked)
}

func (s *Signature) keepalive() {
	s.accessed.Store(time.Now().UnixNano())
}

func (s *Signature) lastAccessed() time.Time {
	return time.Unix(0, s.accessed.Load())
}

func (s *Signature) Status() sys.SignatureStatus {
	return sys.SignatureStatus(s.status.Load())
}

func (s *Signature) Type() Type {
	return Type(s.typ.Load())
}

func (s *Signature) Exists() bool {
	return s.exists.Load()
}

func (s *Signature) setStatus(v sys.SignatureStatus) {
	s.status.Store(uint32(v))
}

func (s *Signature) setType(t Type) {
	s.typ.Store(uint32(t))
}

func (s *Signature) setExists() {
	s.exists.Store(true)
}

func (s *Signature) IsTrusted() bool {
	return s.Status() == sys.SignatureTrusted
}

// Cert returns the certificate, or nil if not yet parsed.
func (s *Signature) Cert() *sys.Cert {
	return s.cert.Load()
}

// setCert uses a aingle atomic store to initialize a valid pointer
// cert pointer exactly once. Any reader seeing non-nil is guaranteed
// to see the fully initialised Cert struct.
func (s *Signature) setCert(cert *sys.Cert) {
	s.cert.CompareAndSwap(nil, cert)
}

// HasCertificate returns true if this signature holds a certificate.
func (s *Signature) HasCertificate() bool {
	return s.cert.Load() != nil
}

// verifyFile performs a trust verification action on the PE file
// by passing the inquiry to a trust provider that supports the action
// identifier.
func (s *Signature) verifyFile() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	trust := sys.NewWintrustData(sys.WtdChoiceFile)
	defer trust.Close()
	status, err := trust.VerifyFile(s.Path)
	s.setStatus(status)
	return err
}

// verifyCatalog verifies the catalog-based file signature.
func (s *Signature) verifyCatalog(catalog sys.Cat) error {
	status, err := catalog.Verify(s.Path)
	s.setStatus(status)
	return err
}

// parseCertificate parses the certificate data for catalog-based
// or PE signatures if the parameter is set to false.
func (s *Signature) parseCertificate(onlyCatalog bool) (*sys.Cert, error) {
	if s == nil {
		return nil, ErrNilSignature
	}

	// the certificate already exists
	if s.HasCertificate() {
		return s.Cert(), nil
	}
	if !s.Exists() {
		return nil, ErrNoSignature
	}

	if !onlyCatalog {
		// parse PE certificate
		f, err := pe.ParseFile(s.Path, pe.WithSecurity())
		if err != nil {
			goto cat
		}
		return f.Cert, nil
	}

cat:
	if !sys.IsWintrustFound() {
		return nil, ErrWintrustUnavailable
	}
	// parse catalog certificate
	catalog := sys.NewCatalog()
	if err := catalog.Open(s.Path); err != nil {
		return nil, err
	}
	defer catalog.Close()
	return catalog.ParseCertificate()
}
