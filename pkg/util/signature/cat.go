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
	"github.com/rabbitstack/fibratus/pkg/sys"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"unsafe"
)

// IsCatalogSigned determines if the provided file is catalog signed.
func IsCatalogSigned(filename string) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// acquire handle to a catalog administrator context
	var catalogAdmin windows.Handle
	err := sys.CryptCatalogAdminAcquireContext(&catalogAdmin, nil, nil, 0, 0)
	if err != nil {
		return false
	}
	defer sys.CryptCatalogAdminReleaseContext(catalogAdmin, 0)

	// calculate file hash
	file, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer file.Close()
	size := uint32(100)
	hash := make([]byte, size)
	err = sys.CryptCatalogAdminCalcHashFromFileHandle(
		catalogAdmin,
		file.Fd(),
		&size,
		uintptr(unsafe.Pointer(&hash[0])), 0,
	)
	if err != nil {
		return false
	}

	// enumerate catalogs that contain the calculated hash.
	// If no catalogs are found, we can deduce the file is
	// not catalog signed
	catalog := sys.CryptCatalogAdminEnumCatalogFromHash(
		catalogAdmin,
		uintptr(unsafe.Pointer(&hash[0])),
		size, 0, nil,
	)
	defer sys.CryptCatalogAdminReleaseCatalogContext(catalogAdmin, catalog, 0)
	return catalog != 0
}

// verifyCatalogSignature calculates the provided file hash and tries
// to locate the hash within the catalog. If the hash is found in the
// catalog, the signature verification process is performed.
func verifyCatalogSignature(filename string) bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// acquire handle to a catalog administrator context
	var catalogAdmin windows.Handle
	err := sys.CryptCatalogAdminAcquireContext(&catalogAdmin, nil, nil, 0, 0)
	if err != nil {
		return false
	}
	defer sys.CryptCatalogAdminReleaseContext(catalogAdmin, 0)

	// calculate file hash
	file, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer file.Close()
	size := uint32(100)
	hash := make([]byte, size)
	err = sys.CryptCatalogAdminCalcHashFromFileHandle(
		catalogAdmin,
		file.Fd(),
		&size,
		uintptr(unsafe.Pointer(&hash[0])), 0,
	)
	if err != nil {
		return false
	}

	// enumerate catalogs that contain the calculated hash
	catalog := sys.CryptCatalogAdminEnumCatalogFromHash(
		catalogAdmin,
		uintptr(unsafe.Pointer(&hash[0])),
		size, 0, nil,
	)
	if catalog == 0 {
		return false
	}
	defer sys.CryptCatalogAdminReleaseCatalogContext(catalogAdmin, catalog, 0)
	var catalogInfo sys.CatalogInfo
	catalogInfo.Size = uint32(unsafe.Sizeof(sys.CatalogInfo{}))
	err = sys.CryptCatalogInfoFromContext(catalog, &catalogInfo, 0)
	if err != nil {
		return false
	}
	t := sys.NewWintrustData(sys.WtdChoiceCatalog)
	defer t.Close()
	return t.VerifyCatalog(file.Fd(), filename, catalogAdmin, catalogInfo, hash, size)
}
