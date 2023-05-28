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
	"github.com/rabbitstack/fibratus/pkg/util/format"
	"golang.org/x/sys/windows"
	"os"
	"runtime"
	"unsafe"
)

// isCatalogSigned determines if the provided file is catalog signed.
func isCatalogSigned(filename string) bool {
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
	//nolint:errcheck
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
	if catalog == 0 {
		return false
	}
	return true
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
	//nolint:errcheck
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
	//nolint:errcheck
	defer sys.CryptCatalogAdminReleaseCatalogContext(catalogAdmin, catalog, 0)
	var catalogInfo sys.CatalogInfo
	catalogInfo.Size = uint32(unsafe.Sizeof(sys.CatalogInfo{}))
	err = sys.CryptCatalogInfoFromContext(catalog, &catalogInfo, 0)
	if err != nil {
		return false
	}

	// tag is a hexadecimal representation of the hash of the file
	tag := windows.StringToUTF16Ptr(format.BytesToHex(hash[:size]))

	cat := &sys.WintrustCatalogInfo{
		Size:            uint32(unsafe.Sizeof(sys.WintrustCatalogInfo{})),
		CatalogFilePath: uintptr(unsafe.Pointer(&catalogInfo.Name[0])),
		MemberFilePath:  uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(filename))),
		MemberFile:      windows.Handle(file.Fd()),
		MemberTag:       uintptr(unsafe.Pointer(tag)),
		FileHash:        uintptr(unsafe.Pointer(&hash[0])),
		FileHashSize:    size,
		CatalogAdmin:    catalogAdmin,
	}
	data := &sys.WintrustData{
		Size:             uint32(unsafe.Sizeof(sys.WintrustData{})),
		UIChoice:         sys.WtdUINone,
		RevocationChecks: sys.WtdRevokeNone,
		UnionChoice:      sys.WtdChoiceCatalog,
		Union:            uintptr(unsafe.Pointer(cat)),
		StateAction:      sys.WtdStateActionVerify,
		ProviderFlags:    sys.WtdSaferFlag,
	}

	status, err := sys.WinVerifyTrust(windows.InvalidHandle, &WintrustActionGenericVerifyV2, data)
	// release stata data by specifying the corresponding action
	data.StateAction = sys.WtdStateActionClose
	_, _ = sys.WinVerifyTrust(windows.InvalidHandle, &WintrustActionGenericVerifyV2, data)
	if err != nil {
		return false
	}
	if status != 0 {
		return false
	}
	return true
}
