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
	"errors"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"runtime"
)

const (
	// UncheckedLevel specifies signature unchecked level
	UncheckedLevel uint32 = 0
	// UnsignedLevel specifies signature unsigned level
	UnsignedLevel uint32 = 1
	// AuthenticodeLevel determines the object is Authenticode signed
	AuthenticodeLevel uint32 = 4

	// None indicates non-existent signature
	None uint32 = 0
	// Embedded indicates the signature is baked into the PE object
	Embedded uint32 = 1
	// Catalog indicates the executable or DLL signature is stored in the catalog
	Catalog uint32 = 3
)

// ErrNotSigned represents the error which is raised when the image lacks the signature
var ErrNotSigned = errors.New("image is not signed")

// ErrWintrustUnavailable represents the error which is raised when wintrust platfrom is not available
var ErrWintrustUnavailable = errors.New("wintrust is not available")

// Types enum defines signature types which verified the image.
var Types = map[uint32]string{
	0: "NONE",             // unsigned or verification hasn't been attempted
	1: "EMBEDDED",         // embedded signature
	2: "CACHED",           // cached signature; presence of a CI EA means the file was previously verified
	3: "CATALOG_CACHED",   // cached catalog verified via Catalog Database or searching catalog directly
	4: "CATALOG_UNCACHED", // uncached catalog verified via Catalog Database or searching catalog directly
	5: "CATALOG_HINT",     // successfully verified using an EA that informs CI that catalog to try first
	6: "PACKAGE_CATALOG",  // AppX / MSIX package catalog verified
	7: "FILE_VERIFIED",    // the file was verified
}

// Levels enum defines all possible image signature levels at which the code was verified.
var Levels = map[uint32]string{
	0:  "UNCHECKED",    // signing level hasn't yet been checked
	1:  "UNSIGNED",     // file is unsigned or has no signature that passes the active policies
	2:  "ENTERPRISE",   // trusted by Windows Defender Application Control policy
	3:  "DEVELOPER",    // developer signed code
	4:  "AUTHENTICODE", // Authenticode signed
	5:  "STORE_PPL",    // Microsoft Store signed app PPL (Protected Process Light)
	6:  "STORE",        // Microsoft Store-signed
	7:  "ANTIMALWARE",  // signed by an Antimalware vendor whose product is using AMPPL
	8:  "MICROSOFT",    // Microsoft signed
	9:  "CUSTOM_4",
	10: "CUSTOM_5",
	11: "DYNAMIC_CODEGEN", // only used for signing of the .NET NGEN compiler
	12: "WINDOWS",         // Windows signed
	13: "CUSTOM_7",
	14: "WINDOWS_TCB", // Windows Trusted Computing Base signed
	15: "CUSTOM_6",
}

// Signature represents the signature status.
type Signature struct {
	// Type specifies the signature type. If the image is not signed, the
	// type is equal to None.
	Type uint32
	// Level specifies the signature level at which the code was signed.
	Level uint32
	// Cert represents certificate information for the particular signature.
	Cert *sys.Cert
	// filename represents the name of the executable image/DLL/driver
	filename string
}

func (s *Signature) IsSigned() bool       { return s.Type != None }
func (s *Signature) IsTrusted() bool      { return s.Level != UncheckedLevel && s.Level != UnsignedLevel }
func (s *Signature) HasCertificate() bool { return s.Cert != nil }

// VerifyEmbedded performs a trust verification action on the PE file
// by passing the inquiry to a trust provider that supports the action
// identifier.
func (s *Signature) VerifyEmbedded() bool {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	trust := sys.NewWintrustData(sys.WtdChoiceFile)
	defer trust.Close()
	return trust.VerifyFile(s.filename)
}

// VerifyCatalog verifies the catalog-based file signature.
func (s *Signature) VerifyCatalog() bool {
	catalog := sys.NewCatalog()
	err := catalog.Open(s.filename)
	if err != nil {
		return false
	}
	defer catalog.Close()
	return catalog.Verify(s.filename)
}
