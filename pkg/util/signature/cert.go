//go:build windows

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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/secDre4mer/pkcs7"
)

const (
	winCertHeaderSize         = 8      // dwLength + wRevision + wCertificateType
	winCertTypePKCSSignedData = 0x0002 // WIN_CERT_TYPE_PKCS_SIGNED_DATA
	maxCertBlobSize           = 4 << 20
)

// Offsets and magic numbers of the PE headers that are needed to locate
// the certificate table. Nothing else in the image is ever read.
const (
	dosHeaderSize          = 64
	dosMagic               = 0x5a4d     // "MZ"
	dosNTHeaderOffset      = 0x3c       // e_lfanew
	ntSignature            = 0x00004550 // "PE\0\0"
	fileHeaderSize         = 20
	fileHeaderOptSizeOff   = 16 // SizeOfOptionalHeader within IMAGE_FILE_HEADER
	optionalMagicPE32      = 0x10b
	optionalMagicPE32Plus  = 0x20b
	pe32DataDirsOffset     = 96  // IMAGE_OPTIONAL_HEADER32.DataDirectory
	pe32PlusDataDirsOffset = 112 // IMAGE_OPTIONAL_HEADER64.DataDirectory
	dataDirEntrySize       = 8
	dataDirSecurity        = 4 // IMAGE_DIRECTORY_ENTRY_SECURITY
)

// pkcs7ParseMu serializes every call into pkcs7.Parse in the process.
var pkcs7ParseMu sync.Mutex

// ParsePKCS7 parses the DER/BER encoded PKCS#7 package. It is a goroutine-safe
// wrapper around pkcs7.Parse. Always use it instead of calling pkcs7.Parse
// directly.
func parsePKCS7(data []byte) (*pkcs7.PKCS7, error) {
	pkcs7ParseMu.Lock()
	defer pkcs7ParseMu.Unlock()
	return pkcs7.Parse(data)
}

// errNotPE is wrapped by the errors returned for files that aren't PE images.
var errNotPE = errors.New("not a PE image")

// parseSecurityDirectory reads the PE headers and the WIN_CERTIFICATE blob of
// the executable or DLL, and returns the signer certificate of the embedded
// Authenticode signature.
//
// The returned boolean reports whether the image carries a certificate table.
// It says nothing about trust, which is the WinVerifyTrust's job. When the
// image is signed but the signature can't be decoded, the function returns
// true, a nil certificate, and the reason as the error. This matters for the
// caller: a signed image with a signature blob we can't decode must still be
// verified as an embedded signature, rather than be treated as unsigned and
// sent down the catalog lookup path.
//
// The certificate table is placed at the very end of the image, so the file is
// accessed with positioned reads. The cost is a few hundred bytes of headers plus
// the signature blob regardless of the image size.
func parseSecurityDirectory(path string) (bool, *sys.Cert, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return false, nil, err
	}

	return parseSecurityDirectoryAt(f, fi.Size())
}

// parseSecurityDirectoryAt is parseSecurityDirectory for an image that is
// accessible through r, and has the given size in bytes.
func parseSecurityDirectoryAt(r io.ReaderAt, size int64) (bool, *sys.Cert, error) {
	dir, err := securityDirectory(r)
	if err != nil {
		return false, nil, err
	}

	// for the security directory, the address is a raw file offset, not an RVA
	if dir.offset == 0 || dir.size == 0 {
		return false, nil, nil
	}

	off, n := int64(dir.offset), int64(dir.size)
	if off+n > size {
		return true, nil, fmt.Errorf("security directory [%d, %d) exceeds file size %d", off, off+n, size)
	}

	cert, err := readSignerCert(r, off, n)
	if err != nil {
		return true, nil, err
	}

	return true, cert, nil
}

type dataDirectory struct {
	offset, size uint32
}

// securityDirectory walks the DOS, NT, and optional headers to find the
// IMAGE_DIRECTORY_ENTRY_SECURITY data directory. It performs a handful of tiny
// reads, and unlike debug/pe, it never touches the COFF symbol table which is
// potentially huge on unstripped binaries.
func securityDirectory(r io.ReaderAt) (dataDirectory, error) {
	var dir dataDirectory

	var dos [dosHeaderSize]byte
	if err := readFullAt(r, dos[:], 0); err != nil {
		return dir, fmt.Errorf("%w: reading DOS header: %v", errNotPE, err)
	}
	if binary.LittleEndian.Uint16(dos[:]) != dosMagic {
		return dir, fmt.Errorf("%w: bad DOS signature", errNotPE)
	}
	ntOff := int64(binary.LittleEndian.Uint32(dos[dosNTHeaderOffset:]))

	var nt [4 + fileHeaderSize]byte
	if err := readFullAt(r, nt[:], ntOff); err != nil {
		return dir, fmt.Errorf("%w: reading NT headers: %v", errNotPE, err)
	}
	if binary.LittleEndian.Uint32(nt[:]) != ntSignature {
		return dir, fmt.Errorf("%w: bad NT signature", errNotPE)
	}

	optOff := ntOff + int64(len(nt))
	optSize := int64(binary.LittleEndian.Uint16(nt[4+fileHeaderOptSizeOff:]))
	if optSize < 2 {
		return dir, fmt.Errorf("%w: no optional header", errNotPE)
	}

	var magic [2]byte
	if err := readFullAt(r, magic[:], optOff); err != nil {
		return dir, fmt.Errorf("%w: reading optional header: %v", errNotPE, err)
	}
	var dirsOff int64
	switch m := binary.LittleEndian.Uint16(magic[:]); m {
	case optionalMagicPE32:
		dirsOff = pe32DataDirsOffset
	case optionalMagicPE32Plus:
		dirsOff = pe32PlusDataDirsOffset
	default:
		return dir, fmt.Errorf("%w: unknown optional header magic %#x", errNotPE, m)
	}

	// an optional header too small to hold the security entry has no
	// certificate table
	entryOff := dirsOff + dataDirSecurity*dataDirEntrySize
	if optSize < entryOff+dataDirEntrySize {
		return dir, nil
	}

	// NumberOfRvaAndSizes immediately precedes the data directory array
	var n [4]byte
	if err := readFullAt(r, n[:], optOff+dirsOff-4); err != nil {
		return dir, fmt.Errorf("%w: reading data directories: %v", errNotPE, err)
	}
	if binary.LittleEndian.Uint32(n[:]) <= dataDirSecurity {
		return dir, nil
	}

	var e [dataDirEntrySize]byte
	if err := readFullAt(r, e[:], optOff+entryOff); err != nil {
		return dir, fmt.Errorf("%w: reading security directory: %v", errNotPE, err)
	}
	dir.offset = binary.LittleEndian.Uint32(e[:4])
	dir.size = binary.LittleEndian.Uint32(e[4:])

	return dir, nil
}

// readFullAt reads exactly len(buf) bytes at the given offset.
func readFullAt(r io.ReaderAt, buf []byte, off int64) error {
	n, err := r.ReadAt(buf, off)
	if n == len(buf) {
		return nil
	}
	if err == nil || err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

func readSignerCert(r io.ReaderAt, off, size int64) (*sys.Cert, error) {
	if size < winCertHeaderSize {
		return nil, errors.New("security directory too small")
	}

	var hdr [winCertHeaderSize]byte
	if err := readFullAt(r, hdr[:], off); err != nil {
		return nil, fmt.Errorf("read WIN_CERTIFICATE header: %w", err)
	}
	length := int64(binary.LittleEndian.Uint32(hdr[0:4]))
	certType := binary.LittleEndian.Uint16(hdr[6:8])

	switch {
	case certType != winCertTypePKCSSignedData:
		return nil, fmt.Errorf("unsupported certificate type %#x", certType)
	case length < winCertHeaderSize || length > size:
		return nil, fmt.Errorf("invalid certificate length %d", length)
	case length-winCertHeaderSize > maxCertBlobSize:
		return nil, fmt.Errorf("certificate blob too large: %d", length)
	}

	blob := make([]byte, length-winCertHeaderSize)
	if err := readFullAt(r, blob, off+winCertHeaderSize); err != nil {
		return nil, fmt.Errorf("read certificate blob: %w", err)
	}

	// pkcs7.Parse isn't goroutine-safe, so it must go through the shared wrapper
	p7, err := parsePKCS7(blob)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#7 signature: %w", err)
	}
	if len(p7.Signers) == 0 {
		return nil, errors.New("signature has no signers")
	}

	// The signer is identified by the issuer name AND the serial number. The
	// serial number alone is unique only within a single issuer, and the
	// certificates in the set aren't guaranteed to be ordered with the signer first.
	signer := p7.Signers[0].IssuerAndSerialNumber
	if signer.SerialNumber == nil {
		return nil, errors.New("signer has no serial number")
	}
	for _, cert := range p7.Certificates {
		if cert.SerialNumber != nil &&
			cert.SerialNumber.Cmp(signer.SerialNumber) == 0 &&
			bytes.Equal(cert.RawIssuer, signer.IssuerName.FullBytes) {
			return sys.NewCert(cert), nil
		}
	}

	return nil, errors.New("signer certificate not found")
}
