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
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"time"

	"github.com/rabbitstack/fibratus/pkg/sys"
	"go.mozilla.org/pkcs7"
)

const (
	winCertHeaderSize         = 8      // dwLength + wRevision + wCertificateType
	winCertTypePKCSSignedData = 0x0002 // WIN_CERT_TYPE_PKCS_SIGNED_DATA
	maxCertBlobSize           = 4 << 20
	readSize                  = 8 * 1024 * 1024 // 8 MB
)

// parseSecurityDirectory reads only the PE headers and the WIN_CERTIFICATE blob,
// of the executable or DLL file and returns true and the signier certificiate if
// the file has a valid signature.
func parseSecurityDirectory(path string) (bool, *sys.Cert, error) {
	buf, err := sys.ReadFile(path, readSize, time.Millisecond*500)
	if err != nil {
		return false, nil, err
	}

	r := bytes.NewReader(buf)
	f, err := pe.NewFile(r)
	if err != nil {
		return false, nil, err
	}

	var dir pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if oh.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			dir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		}
	case *pe.OptionalHeader64:
		if oh.NumberOfRvaAndSizes > pe.IMAGE_DIRECTORY_ENTRY_SECURITY {
			dir = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_SECURITY]
		}
	default:
		return false, nil, errors.New("pe: no optional header")
	}

	// for the security directory, VirtualAddress is a raw file offset, not an RVA
	if dir.VirtualAddress == 0 || dir.Size == 0 {
		return false, nil, nil
	}

	off, size := int64(dir.VirtualAddress), int64(dir.Size)
	if int(off+size) > len(buf) {
		return false, nil, errors.New("security directory exceeds file size")
	}
	cert, err := readSignerCert(r, off, size)
	return err == nil && cert != nil, cert, err
}

func readSignerCert(r *bytes.Reader, off, size int64) (*sys.Cert, error) {
	if size < winCertHeaderSize {
		return nil, errors.New("security directory too small")
	}

	var hdr [winCertHeaderSize]byte
	if _, err := r.ReadAt(hdr[:], off); err != nil {
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
	if _, err := r.ReadAt(blob, off+winCertHeaderSize); err != nil {
		return nil, fmt.Errorf("read certificate blob: %w", err)
	}

	p7, err := pkcs7.Parse(blob)
	if err != nil {
		return nil, err
	}
	if len(p7.Signers) == 0 {
		return nil, errors.New("signature has no signers")
	}

	certInfo := &sys.Cert{}
	serialNumber := p7.Signers[0].IssuerAndSerialNumber.SerialNumber
	for _, cert := range p7.Certificates {
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

		return certInfo, nil
	}

	return nil, errors.New("signer certificate not found")
}
