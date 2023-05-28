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
	"golang.org/x/sys/windows"
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

// IsWintrustFound indicates if the wintrust DLL is present in the system.
func IsWintrustFound() bool { return modwintrust.Load() == nil }
