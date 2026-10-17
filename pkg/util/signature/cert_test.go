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
	"path/filepath"
	"testing"

	"github.com/rabbitstack/fibratus/pkg/pe"
)

func TestReadSecurityMatchesParser(t *testing.T) {
	t.Skip()
	files, _ := filepath.Glob(`C:\Windows\System32\*.dll`)
	if len(files) > 300 {
		files = files[:300]
	}
	for _, path := range files {
		old, err := pe.ParseFile(path, pe.WithSecurity())
		if err != nil || old == nil {
			continue
		}
		signed, cert, err := parseSecurityDirectory(path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if old.IsSigned() != signed {
			t.Errorf("%s: signed old=%t new=%t", path, old.IsSigned(), signed)
		}
		if old.Cert != nil && (cert == nil ||
			old.Cert.Subject != cert.Subject ||
			old.Cert.Issuer != cert.Issuer ||
			old.Cert.SerialNumber != cert.SerialNumber) {
			t.Errorf("%s: cert mismatch old=%+v new=%+v err=%v", path, old.Cert, cert, err)
		}
	}
}
