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
	"github.com/rabbitstack/fibratus/pkg/util/format"
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

// IsWintrustFound indicates if the wintrust DLL is present in the system.
func IsWintrustFound() bool { return modwintrust.Load() == nil }
