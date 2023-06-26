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
	"encoding/hex"
	"github.com/rabbitstack/fibratus/pkg/pe"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"go.mozilla.org/pkcs7"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"reflect"
	"runtime"
	"unsafe"
)

// Cat represents the catalog that acts as a digital signature
// for an arbitrary collection of files. A catalog file contains
// a collection of cryptographic hashes, or thumbprints. Each thumbprint
// corresponds to a file that is included in the collection.
type Cat struct {
	admin       windows.Handle
	catalog     windows.Handle
	file        *os.File
	catalogInfo sys.CatalogInfo

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
	err := sys.CryptCatalogAdminAcquireContext(&c.admin, nil, nil, 0, 0)
	if err != nil {
		return err
	}
	// calculate file hash
	c.file, err = os.Open(filename)
	if err != nil {
		return err
	}
	err = sys.CryptCatalogAdminCalcHashFromFileHandle(
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
	c.catalog = sys.CryptCatalogAdminEnumCatalogFromHash(
		c.admin,
		uintptr(unsafe.Pointer(&c.hash[0])),
		c.size, 0, nil,
	)
	c.catalogInfo.Size = uint32(unsafe.Sizeof(c.catalogInfo))
	err = sys.CryptCatalogInfoFromContext(c.catalog, &c.catalogInfo, 0)
	if err != nil {
		return ErrNotSigned
	}
	return nil
}

// IsCatalogSigned determines if the file is catalog-signed.
func (c *Cat) IsCatalogSigned() bool {
	return c.catalog != 0
}

// Verify verifies the signature of the given file against the catalog.
func (c *Cat) Verify(filename string) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	trust := sys.NewWintrustData(sys.WtdChoiceCatalog)
	defer trust.Close()
	if c.file == nil {
		panic("catalog is not opened")
	}
	return trust.VerifyCatalog(c.file.Fd(), filename, c.admin, c.catalogInfo, c.hash, c.size)
}

// ParseCertificate parses the catalog certificate.
func (c *Cat) ParseCertificate() (*pe.Cert, error) {
	f, err := os.Open(c.catalogInfo.CatalogFile())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cert, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	pkcs, err := pkcs7.Parse(cert)
	if err != nil {
		return nil, err
	}

	certInfo := &pe.Cert{}
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
		defer sys.CryptCatalogAdminReleaseContext(c.admin, 0)
	}
	var err error
	if c.admin != 0 && c.catalog != 0 {
		err = sys.CryptCatalogAdminReleaseCatalogContext(c.admin, c.catalog, 0)
	}
	if c.file != nil {
		return multierror.Wrap(c.file.Close(), err)
	}
	return err
}
