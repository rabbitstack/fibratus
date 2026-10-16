//go:build windows

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

package sys

import (
	libytes "bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/golang/groupcache/singleflight"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	"github.com/rabbitstack/fibratus/pkg/util/format"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"
	"golang.org/x/sys/windows"
)

const (
	// WtdUIAll display all UI interface.
	WtdUIAll = 1
	// WtdUINone display no UI.
	WtdUINone = 2
	// WtdUINoBad do not display any negative UI
	WtdUINoBad = 3
	// WtdUINoGood do not display any positive UI
	WtdUINoGood = 4
	// WtdRevokeNone dictates that no additional revocation checking
	// will be done when the WtdRevokeNone flag is used in conjunction
	// with the HTTPSPROV_ACTION value set in the action parameter of the
	// WinVerifyTrust function. To ensure the WinVerifyTrust function does
	// not attempt any network retrieval when verifying code signatures,
	// WTD_CACHE_ONLY_URL_RETRIEVAL must be set in the ProviderFlags parameter.
	WtdRevokeNone = 0
	// WtdChoiceFile specifies the file object is verified by the trust provider.
	WtdChoiceFile = 1
	// WtdChoiceCatalog specifies the file object is verified through catalog by the trust provider.
	WtdChoiceCatalog = 2
	// WtdStateActionVerify verifies the trust of the object (typically a file)
	// that is specified by the UnionChoice member. The StateData member will
	// receive a handle to the state data. This handle must be freed by specifying
	// the WtdStateActionClose action in a subsequent call.
	WtdStateActionVerify = 0x00000001
	// WtdStateActionClose frees the StateData member previously allocated with
	// the WtdStateActionVerify action. This action must be specified for every use
	// of the WtdStateActionVerify action.
	WtdStateActionClose = 0x00000002
	// WtdSaferFlag is the trust provider flag
	WtdSaferFlag = 0x100
	// WtdCacheOnlyURLRetrieval use only the local cache for revocation checks. Prevents revocation checks over the network.
	WtdCacheOnlyURLRetrieval = 0x1000
)

const (
	trustSignatureOk          = 0
	trustErrNoSignature       = 0x800b0100
	trustErrExplicitDistrust  = 0x800B0111
	trustErrSystem            = 0x80096001
	trustErrBadDigest         = 0x80096010
	trustErrSubjectNotTrusted = 0x800B0003
	trustErrTimestamp         = 0x80096005
	trustMalformedSignature   = 0x80096011
	cryptErrSecuritySettings  = 0x80092026
	certErrExpired            = 0x800B0101
)

// SignatureStatus defines the signature status
type SignatureStatus uint8

const (
	SignatureNotTrusted SignatureStatus = iota
	SignatureTrusted
	SignatureExpired
	SignatureBadDigest
	SignatureBadTimestamp
	SignatureMalformed
	SignatureEndpointError
)

func (s SignatureStatus) String() string {
	switch s {
	case SignatureNotTrusted:
		return "NotTrusted"
	case SignatureTrusted:
		return "Trusted"
	case SignatureExpired:
		return "Expired"
	case SignatureBadDigest:
		return "BadDigest"
	case SignatureBadTimestamp:
		return "BadTimestamp"
	case SignatureMalformed:
		return "Malformed"
	case SignatureEndpointError:
		return "EndpointError"
	default:
		return fmt.Sprintf("%d", uint8(s))
	}
}

// WintrustActionGenericVerifyV2 is the action that indicates the file or object should be verified by using the Authenticode policy provider.
var WintrustActionGenericVerifyV2 = windows.GUID{Data1: 0xaac56b, Data2: 0xcd44, Data3: 0x11d0, Data4: [8]byte{0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee}}

// WintrustData structure is used when calling WinVerifyTrust
// to pass necessary information into the trust providers.
type WintrustData struct {
	Size                          uint32
	PolicyCallbackBuffer          uintptr
	SubjectInterfacePackageBuffer uintptr
	UIChoice                      uint32
	RevocationChecks              uint32
	UnionChoice                   uint32
	Union                         uintptr // C union
	StateAction                   uint32
	StateData                     windows.Handle
	URLReference                  uintptr
	ProviderFlags                 uint32
	UIContext                     uint32
	SignatureSettings             *WintrustSignatureSettings
}

// NewWintrustData creates a new instance of WintrustData prepared
// to verify file or catalog trust.
func NewWintrustData(choice uint32) *WintrustData {
	return &WintrustData{
		Size:             uint32(unsafe.Sizeof(WintrustData{})),
		UnionChoice:      choice,
		UIChoice:         WtdUINone,
		RevocationChecks: WtdRevokeNone,
		StateAction:      WtdStateActionVerify,
		ProviderFlags:    WtdSaferFlag | WtdCacheOnlyURLRetrieval,
	}
}

func (t *WintrustData) verifyTrust() (SignatureStatus, error) {
	status, err := WinVerifyTrust(windows.InvalidHandle, &WintrustActionGenericVerifyV2, t)
	switch status {
	case trustSignatureOk:
		return SignatureTrusted, nil
	case trustErrNoSignature, trustErrExplicitDistrust, trustErrSubjectNotTrusted, cryptErrSecuritySettings:
		return SignatureNotTrusted, err
	case trustErrSystem:
		return SignatureEndpointError, err
	case trustErrBadDigest:
		return SignatureBadDigest, err
	case trustErrTimestamp:
		return SignatureBadTimestamp, err
	case trustMalformedSignature:
		return SignatureMalformed, err
	case certErrExpired:
		return SignatureExpired, err
	default:
		return SignatureNotTrusted, err
	}
}

// VerifyFile verifies the provided file trust. The trust provider
// should perform the verification action without the user's assistance.
// This is achieved by providing INVALID_HANDLE_VALUE as a first parameter
// in the WinVerifyTrust call.
func (t *WintrustData) VerifyFile(filename string) (SignatureStatus, error) {
	fileinfo := &WintrustFileInfo{
		Size:     uint32(unsafe.Sizeof(WintrustFileInfo{})),
		FilePath: windows.StringToUTF16Ptr(filename),
	}
	t.Union = uintptr(unsafe.Pointer(fileinfo))

	status, err := t.verifyTrust()
	runtime.KeepAlive(fileinfo)

	return status, err
}

// VerifyCatalog verifies the trust of the file signed by catalog-based certificate.
func (t *WintrustData) VerifyCatalog(
	fd uintptr,
	filename string,
	catalogAdmin windows.Handle,
	catalog CatalogInfo,
	hash []byte,
	hashSize uint32,
) (SignatureStatus, error) {
	// convert strings to UTF-16 and hold explicit Go references.
	// Converting directly to uintptr in the struct literal would
	// allow the GC to collect these before WinVerifyTrust reads them
	s := format.BytesToHex(hash[:hashSize])
	tag := windows.StringToUTF16Ptr(s)
	path := windows.StringToUTF16Ptr(filename)

	catinfo := &WintrustCatalogInfo{
		Size:            uint32(unsafe.Sizeof(WintrustCatalogInfo{})),
		CatalogFilePath: uintptr(unsafe.Pointer(&catalog.Name[0])),
		MemberFilePath:  uintptr(unsafe.Pointer(path)),
		MemberFile:      windows.Handle(fd),
		MemberTag:       uintptr(unsafe.Pointer(tag)),
		FileHash:        uintptr(unsafe.Pointer(&hash[0])),
		FileHashSize:    hashSize,
		CatalogAdmin:    catalogAdmin,
	}
	t.Union = uintptr(unsafe.Pointer(catinfo))

	status, err := t.verifyTrust()

	// KeepAlive pins every object whose address was passed into
	// WinVerifyTrust via a uintptr field. Without these, the GC
	// is permitted to collect them as soon as their last Go-visible
	// use is seenm which may be before verifyTrust returns
	runtime.KeepAlive(tag)
	runtime.KeepAlive(path)
	runtime.KeepAlive(hash)
	runtime.KeepAlive(catalog)
	runtime.KeepAlive(catinfo)

	return status, err
}

// Close disposes state data by specifying the corresponding action
func (t *WintrustData) Close() error {
	t.StateAction = WtdStateActionClose
	status, err := WinVerifyTrust(windows.InvalidHandle, &WintrustActionGenericVerifyV2, t)
	if err != nil {
		return err
	}
	if status != 0 {
		return windows.GetLastError()
	}
	return nil
}

// WintrustSignatureSettings structure can be used to specify the signatures on a file.
type WintrustSignatureSettings struct {
	Size                uint32
	Index               uint32
	Flags               uint32
	SecondarySignatures uint32
	SignatureIndex      uint32
	CryptoPolicy        uintptr // pointer to CERT_STRONG_SIGN_PARA structure
}

// WintrustFileInfo structure is used when calling WinVerifyTrust to verify an individual file.
type WintrustFileInfo struct {
	Size         uint32
	FilePath     *uint16 // file path to be verified
	FileHandle   uintptr // file handle to open file
	KnownSubject *windows.GUID
}

// WintrustCatalogInfo structure is used when calling WinVerifyTrust to verify a member of a Microsoft catalog.
type WintrustCatalogInfo struct {
	Size            uint32
	CatalogVersion  uint32
	CatalogFilePath uintptr
	MemberTag       uintptr
	MemberFilePath  uintptr
	MemberFile      windows.Handle
	FileHash        uintptr
	FileHashSize    uint32
	CatalogContext  uintptr
	CatalogAdmin    windows.Handle
}

// CatalogInfo structure contains the name of a catalog file. This structure is used by
// the CryptCatalogInfoFromContext function.
type CatalogInfo struct {
	Size uint32
	Name [1024]byte
}

// CatalogFile returns the full path to the catalog file.
func (c CatalogInfo) CatalogFile() string {
	n := len(c.Name) / 2
	p := unsafe.Slice((*uint16)(unsafe.Pointer(&c.Name[0])), n)
	return windows.UTF16ToString(p)
}

var isWintrustDLLFound bool
var once sync.Once

// IsWintrustFound indicates if the Wintrust DLL is present in the system.
func IsWintrustFound() bool {
	once.Do(func() {
		isWintrustDLLFound = modwintrust.Load() == nil
		if !isWintrustDLLFound {
			log.Warn("unable to find wintrust.dll library. This will lead to " +
				"PE objects signature verification to be skipped possibly " +
				"causing false positive samples in detection rules relying on " +
				"module signature filter fields")
		}
	})
	return isWintrustDLLFound
}

// Cat represents the catalog that acts as a digital signature
// for an arbitrary collection of files. A catalog file contains
// a collection of cryptographic hashes, or thumbprints. Each thumbprint
// corresponds to a file that is included in the collection.
type Cat struct {
	admin       windows.Handle
	catalog     windows.Handle
	file        *os.File
	catalogInfo CatalogInfo

	hash []byte
	size uint32
}

const initialHashBufSize uint32 = 32 // SHA-1 is 20, SHA-256 is 32; start at 32

// NewCatalog creates an instance of the catalog with default hash size.
func NewCatalog() Cat {
	return Cat{size: initialHashBufSize, hash: make([]byte, initialHashBufSize)}
}

// Open opens the catalog and acquires the hash for the given file. If the
// file is catalog-signed, a valid catalog handle is stored internally.
func (c *Cat) Open(filename string) error {
	// acquire handle to a catalog administrator context
	err := CryptCatalogAdminAcquireContext(&c.admin, nil, nil, 0, 0)
	if err != nil {
		return err
	}
	// calculate file hash
	c.file, err = os.Open(filename)
	if err != nil {
		return err
	}
	err = CryptCatalogAdminCalcHashFromFileHandle(
		c.admin,
		c.file.Fd(),
		&c.size,
		uintptr(unsafe.Pointer(&c.hash[0])), 0,
	)
	if err == windows.ERROR_INSUFFICIENT_BUFFER {
		// reallocate with the new buffer size,
		// rewind the file position and retry
		c.hash = make([]byte, c.size)
		_, _ = c.file.Seek(0, io.SeekStart)
		err = CryptCatalogAdminCalcHashFromFileHandle(
			c.admin,
			c.file.Fd(),
			&c.size,
			uintptr(unsafe.Pointer(&c.hash[0])), 0)
	}

	if err != nil {
		return err
	}

	// enumerate catalogs that contain the calculated hash.
	// If no catalogs are found, we can deduce the file is
	// not catalog signed
	c.catalog = CryptCatalogAdminEnumCatalogFromHash(
		c.admin,
		uintptr(unsafe.Pointer(&c.hash[0])),
		c.size, 0, nil,
	)
	c.catalogInfo.Size = uint32(unsafe.Sizeof(c.catalogInfo))
	return CryptCatalogInfoFromContext(c.catalog, &c.catalogInfo, 0)
}

// IsCatalogSigned determines if the file is catalog-signed.
func (c *Cat) IsCatalogSigned() bool {
	return c.catalog != 0 && c.catalogInfo.CatalogFile() != ""
}

// Verify verifies the signature of the given file against the catalog.
func (c *Cat) Verify(filename string) (SignatureStatus, error) {
	trust := NewWintrustData(WtdChoiceCatalog)
	defer trust.Close()
	if c.file == nil {
		panic("catalog is not opened")
	}
	return trust.VerifyCatalog(c.file.Fd(), filename, c.admin, c.catalogInfo, c.hash, c.size)
}

// certKey is the cache key for parsed cert per catalog file. Keyed by path, size and modification time.
type certKey struct {
	path        string
	size, mtime int64
}

// certEntry is the outcome of parsing a catalog certificate.
type certEntry struct {
	cert    *Cert
	err     error
	expires time.Time // zero for successes, which only age out of the LRU
}

const (
	certsLRUSize = 1024
	// certErrTTL bounds how long a failure to parse a catalog is remembered.
	certErrTTL = 5 * time.Minute
)

var (
	catalogGroup     singleflight.Group
	catalogCertCache = expirable.NewLRU[certKey, *certEntry](certsLRUSize, nil, time.Hour)

	pkcs7ParseMu sync.Mutex
)

// parsePKCS7 parses the DER/BER encoded PKCS#7 package. It is a goroutine-safe
// wrapper around pkcs7.Parse. Always use it instead of calling pkcs7.Parse
// directly.
func parsePKCS7(data []byte) (*pkcs7.PKCS7, error) {
	pkcs7ParseMu.Lock()
	defer pkcs7ParseMu.Unlock()
	return pkcs7.Parse(data)
}

func lookupCert(k certKey) (*certEntry, bool) {
	e, ok := catalogCertCache.Get(k)
	if !ok {
		return nil, false
	}
	// failures carry a deadline shorter than the LRU TTL
	if !e.expires.IsZero() && time.Now().After(e.expires) {
		catalogCertCache.Remove(k)
		return nil, false
	}
	return e, true
}

func parseCatalogCert(path string) (*Cert, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	crt, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	pkcs, err := parsePKCS7(crt)
	if err != nil {
		return nil, err
	}

	if len(pkcs.Signers) == 0 {
		return nil, errors.New("catalog has no signers")
	}
	signer := pkcs.Signers[0].IssuerAndSerialNumber
	if signer.SerialNumber == nil {
		return nil, errors.New("catalog signer has no serial number")
	}

	for _, cert := range pkcs.Certificates {
		if cert.SerialNumber != nil &&
			cert.SerialNumber.Cmp(signer.SerialNumber) == 0 &&
			libytes.Equal(cert.RawIssuer, signer.IssuerName.FullBytes) {
			return NewCert(cert), nil
		}
	}
	return nil, errors.New("catalog signer certificate not found")
}

// ParseCertificate parses the catalog certificate.
func (c *Cat) ParseCertificate() (*Cert, error) {
	path := c.catalogInfo.CatalogFile()
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	size := fi.Size()
	mtime := fi.ModTime().Unix()
	key := certKey{strings.ToLower(path), size, mtime}

	if e, ok := lookupCert(key); ok {
		return e.cert, e.err
	}

	v, _ := catalogGroup.Do(fmt.Sprint(key), func() (any, error) {
		if e, ok := lookupCert(key); ok {
			return e.cert, e.err
		}
		cert, err := parseCatalogCert(path)
		e := &certEntry{cert: cert, err: err}
		if err != nil {
			var pathErr *fs.PathError
			if errors.As(err, &pathErr) {
				return e, nil // I/O failure is not cached
			}
			e.expires = time.Now().Add(certErrTTL)
		}
		catalogCertCache.Add(key, e)
		return e, nil
	})

	e := v.(*certEntry)
	return e.cert, e.err
}

func (c *Cat) Close() error {
	if c.admin != 0 {
		defer CryptCatalogAdminReleaseContext(c.admin, 0)
	}
	var err error
	if c.admin != 0 && c.catalog != 0 {
		err = CryptCatalogAdminReleaseCatalogContext(c.admin, c.catalog, 0)
	}
	if c.file != nil {
		return multierror.Wrap(c.file.Close(), err)
	}
	return err
}

// Cert represents certificate information embedded in the PE or catalog.
type Cert struct {
	// NotBefore specifies the certificate won't be valid before this timestamp.
	NotBefore time.Time `json:"not_before"`

	// NotAfter specifies the certificate won't be valid after this timestamp.
	NotAfter time.Time `json:"not_after"`

	// Issuer represents the certificate authority (CA) that charges customers to issue
	// certificates for them.
	Issuer string `json:"issuer"`

	// Subject indicates the subject of the certificate is the entity its public key is associated
	// with (i.e. the "owner" of the certificate).
	Subject string `json:"subject"`

	// SerialNumber represents the serial number MUST be a positive integer assigned
	// by the CA to each certificate. It MUST be unique for each certificate issued by
	// a given CA (i.e., the issuer name and serial number identify a unique certificate).
	// CAs MUST force the serialNumber to be a non-negative integer.
	// For convenience, we convert the big int to string.
	SerialNumber string `json:"serial_number"`
}

// NewCert builds the certificate info from the X.509 certificate.
func NewCert(cert *x509.Certificate) *Cert {
	certInfo := &Cert{
		SerialNumber: hex.EncodeToString(cert.SerialNumber.Bytes()),
		NotAfter:     cert.NotAfter,
		NotBefore:    cert.NotBefore,
	}

	// issuer information
	if len(cert.Issuer.Country) > 0 {
		certInfo.Issuer = cert.Issuer.Country[0]
	}

	if len(cert.Issuer.Province) > 0 {
		certInfo.Issuer += ", " + cert.Issuer.Province[0]
	}

	if len(cert.Issuer.Locality) > 0 {
		certInfo.Issuer += ", " + cert.Issuer.Locality[0]
	}

	certInfo.Issuer += ", " + cert.Issuer.CommonName

	// subject information
	if len(cert.Subject.Country) > 0 {
		certInfo.Subject = cert.Subject.Country[0]
	}

	if len(cert.Subject.Province) > 0 {
		certInfo.Subject += ", " + cert.Subject.Province[0]
	}

	if len(cert.Subject.Locality) > 0 {
		certInfo.Subject += ", " + cert.Subject.Locality[0]
	}

	if len(cert.Subject.Organization) > 0 {
		certInfo.Subject += ", " + cert.Subject.Organization[0]
	}

	certInfo.Subject += ", " + cert.Subject.CommonName

	return certInfo
}

// Marshal writes certificate info into a raw buffer.
func (c *Cert) Marshal() []byte {
	b := make([]byte, 0)

	before := make([]byte, 0)
	before = c.NotBefore.AppendFormat(before, time.RFC3339Nano)
	b = append(b, bytes.WriteUint16(uint16(len(before)))...)
	b = append(b, before...)

	after := make([]byte, 0)
	after = c.NotAfter.AppendFormat(after, time.RFC3339Nano)
	b = append(b, bytes.WriteUint16(uint16(len(after)))...)
	b = append(b, after...)

	b = append(b, bytes.WriteUint16(uint16(len(c.SerialNumber)))...)
	b = append(b, c.SerialNumber...)
	b = append(b, bytes.WriteUint16(uint16(len(c.Subject)))...)
	b = append(b, c.Subject...)
	b = append(b, bytes.WriteUint16(uint16(len(c.Issuer)))...)
	b = append(b, c.Issuer...)

	return b
}

// Unmarshal decodes cert info from the raw buffer. This method
// assumes the certificate structure size was already read.
func (c *Cert) Unmarshal(b []byte, offset, certSize uint32) error {
	if certSize > uint32(len(b)) {
		return fmt.Errorf("invalid PE cert size. Got %d but max buffer size is %d", certSize, len(b))
	}

	// read not before
	l := bytes.ReadUint16(b[26+offset:])
	buf := b[28+offset:]
	offset += uint32(l)
	if len(buf) > 0 {
		c.NotBefore, _ = time.Parse(time.RFC3339Nano, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
	}

	// read not after
	l = bytes.ReadUint16(b[28+offset:])
	buf = b[30+offset:]
	offset += uint32(l)
	if len(buf) > 0 {
		c.NotAfter, _ = time.Parse(time.RFC3339Nano, string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l]))
	}

	// read serial
	l = bytes.ReadUint16(b[30+offset:])
	buf = b[32+offset:]
	offset += uint32(l)
	c.SerialNumber = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read subject
	l = bytes.ReadUint16(b[32+offset:])
	buf = b[34+offset:]
	offset += uint32(l)
	c.Subject = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	// read issuer
	l = bytes.ReadUint16(b[34+offset:])
	buf = b[36+offset:]
	c.Issuer = string((*[1<<30 - 1]byte)(unsafe.Pointer(&buf[0]))[:l:l])

	return nil
}
