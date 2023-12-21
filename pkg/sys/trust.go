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
	"encoding/hex"
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	"github.com/rabbitstack/fibratus/pkg/util/format"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"reflect"
	"runtime"
	"sync"
	"time"
	"unsafe"
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
)

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
		ProviderFlags:    WtdSaferFlag,
	}
}

// VerifyFile verifies the provided file trust. The trust provider
// should perform the verification action without the user's assistance.
// This is achieved by providing INVALID_HANDLE_VALUE as a first parameter
// in the WinVerifyTrust call.
func (t *WintrustData) VerifyFile(filename string) bool {
	fileinfo := &WintrustFileInfo{
		Size:     uint32(unsafe.Sizeof(WintrustFileInfo{})),
		FilePath: windows.StringToUTF16Ptr(filename),
	}
	t.Union = uintptr(unsafe.Pointer(fileinfo))
	status, err := WinVerifyTrust(windows.InvalidHandle, &WintrustActionGenericVerifyV2, t)
	if status != 0 || err != nil {
		return false
	}
	return true
}

// VerifyCatalog verifies the provided catalog file.
func (t *WintrustData) VerifyCatalog(
	fd uintptr,
	filename string,
	catalogAdmin windows.Handle,
	catalog CatalogInfo,
	hash []byte,
	hasSize uint32,
) bool {
	// tag is a hexadecimal representation of the hash of the file
	tag := windows.StringToUTF16Ptr(format.BytesToHex(hash[:hasSize]))
	catinfo := &WintrustCatalogInfo{
		Size:            uint32(unsafe.Sizeof(WintrustCatalogInfo{})),
		CatalogFilePath: uintptr(unsafe.Pointer(&catalog.Name[0])),
		MemberFilePath:  uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(filename))),
		MemberFile:      windows.Handle(fd),
		MemberTag:       uintptr(unsafe.Pointer(tag)),
		FileHash:        uintptr(unsafe.Pointer(&hash[0])),
		FileHashSize:    hasSize,
		CatalogAdmin:    catalogAdmin,
	}
	t.Union = uintptr(unsafe.Pointer(catinfo))
	status, err := WinVerifyTrust(windows.InvalidHandle, &WintrustActionGenericVerifyV2, t)
	if status != 0 || err != nil {
		return false
	}
	return true
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
	p := (*[unsafe.Sizeof(c.Name) / 2]uint16)(unsafe.Pointer(&c.Name[0]))
	return windows.UTF16ToString(p[:])
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
				"image signature filter fields")
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

const hashSize uint32 = 100

// NewCatalog creates an instance of the catalog with default hash size.
func NewCatalog() Cat {
	return Cat{size: hashSize, hash: make([]byte, hashSize)}
}

// Open opens the catalog and acquires the hash for the given file. If the
// file is catalog-signed, a valid catalog handle is stored internally.
func (c *Cat) Open(filename string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
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
	err = CryptCatalogInfoFromContext(c.catalog, &c.catalogInfo, 0)
	if err != nil {
		return err
	}
	return nil
}

// IsCatalogSigned determines if the file is catalog-signed.
func (c *Cat) IsCatalogSigned() bool {
	return c.catalog != 0 && c.catalogInfo.CatalogFile() != ""
}

// Verify verifies the signature of the given file against the catalog.
func (c *Cat) Verify(filename string) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	trust := NewWintrustData(WtdChoiceCatalog)
	defer trust.Close()
	if c.file == nil {
		panic("catalog is not opened")
	}
	return trust.VerifyCatalog(c.file.Fd(), filename, c.admin, c.catalogInfo, c.hash, c.size)
}

// ParseCertificate parses the catalog certificate.
func (c *Cat) ParseCertificate() (*Cert, error) {
	f, err := os.Open(c.catalogInfo.CatalogFile())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	crt, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	pkcs, err := pkcs7.Parse(crt)
	if err != nil {
		return nil, err
	}

	certInfo := &Cert{}
	serialNumber := pkcs.Signers[0].IssuerAndSerialNumber.SerialNumber
	for _, cert := range pkcs.Certificates {
		if !reflect.DeepEqual(cert.SerialNumber, serialNumber) {
			continue
		}

		certInfo.SerialNumber = hex.EncodeToString(cert.SerialNumber.Bytes())

		certInfo.NotAfter = cert.NotAfter
		certInfo.NotBefore = cert.NotBefore

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

		break
	}
	return certInfo, nil
}

func (c *Cat) Close() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
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
