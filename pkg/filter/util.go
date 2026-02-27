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

package filter

import (
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
	"github.com/rabbitstack/fibratus/pkg/util/loldrivers"
	"github.com/rabbitstack/fibratus/pkg/util/signature"
	"github.com/rabbitstack/fibratus/pkg/util/va"
)

// isLOLDriver interacts with the loldrivers client to determine
// whether the loaded/dropped driver is malicious or vulnerable.
func isLOLDriver(f fields.Field, e *event.Event) (params.Value, error) {
	var filename string

	if e.Category == event.File {
		filename = e.GetParamAsString(params.FilePath)
	} else {
		filename = e.GetParamAsString(params.ImagePath)
	}

	isDriver := filepath.Ext(filename) == ".sys" || e.Params.TryGetBool(params.FileIsDriver)
	if !isDriver {
		return nil, nil
	}
	ok, driver := loldrivers.GetClient().MatchHash(filename)
	if !ok {
		return nil, nil
	}
	if (f == fields.FileIsDriverVulnerable || f == fields.ImageIsDriverVulnerable) && driver.IsVulnerable {
		return true, nil
	}
	if (f == fields.FileIsDriverMalicious || f == fields.ImageIsDriverMalicious) && driver.IsMalicious {
		return true, nil
	}
	return false, nil
}

// initLOLDriversClient initializes the loldrivers client if the filter expression
// contains any of the relevant fields.
func initLOLDriversClient(flds []Field) {
	for _, f := range flds {
		if f.Name == fields.FileIsDriverVulnerable || f.Name == fields.FileIsDriverMalicious ||
			f.Name == fields.ImageIsDriverVulnerable || f.Name == fields.ImageIsDriverMalicious {
			loldrivers.InitClient(loldrivers.WithAsyncDownload())
		}
	}
}

// getFileInfo obtains the file information for created files and loaded modules.
// Appends the file data to the event parameters, so subsequent field extractions
// will already have the needed info.
func getFileInfo(f fields.Field, e *event.Event) (params.Value, error) {
	switch f {
	case fields.FileIsDLL, fields.ImageIsDLL, fields.ModuleIsDLL:
		if e.Params.Contains(params.FileIsDLL) {
			return e.Params.GetBool(params.FileIsDLL)
		}
	case fields.FileIsDriver, fields.ModuleIsDriver, fields.ImageIsDriver:
		if e.Params.Contains(params.FileIsDriver) {
			return e.Params.GetBool(params.FileIsDriver)
		}
	case fields.FileIsExecutable, fields.ImageIsExecutable, fields.ModuleIsExecutable:
		if e.Params.Contains(params.FileIsExecutable) {
			return e.Params.GetBool(params.FileIsExecutable)
		}
	case fields.ImageIsDotnet, fields.ModuleIsDotnet, fields.DllIsDotnet:
		if e.Params.Contains(params.FileIsDotnet) {
			return e.Params.GetBool(params.FileIsDotnet)
		}
	}

	fileinfo, err := fs.GetFileInfo(e.GetParamAsString(params.FilePath))
	if err != nil {
		return nil, err
	}

	e.AppendParam(params.FileIsDLL, params.Bool, fileinfo.IsDLL)
	e.AppendParam(params.FileIsDriver, params.Bool, fileinfo.IsDriver)
	e.AppendParam(params.FileIsExecutable, params.Bool, fileinfo.IsExecutable)
	e.AppendParam(params.FileIsDotnet, params.Bool, fileinfo.IsDotnet)

	switch f {
	case fields.FileIsDLL, fields.ImageIsDLL, fields.ModuleIsDLL:
		return fileinfo.IsDLL, nil
	case fields.FileIsDriver, fields.ModuleIsDriver, fields.ImageIsDriver:
		return fileinfo.IsDriver, nil
	case fields.FileIsExecutable, fields.ImageIsExecutable, fields.ModuleIsExecutable:
		return fileinfo.IsExecutable, nil
	case fields.ImageIsDotnet, fields.ModuleIsDotnet, fields.DllIsDotnet:
		return fileinfo.IsDotnet, nil
	}

	return nil, fmt.Errorf("unexpected field: %s", f)
}

// getSignature tries to find the module signature mapped to the given address.
// If the signature is not found in the cache, then a fresh signature instance
// is created and verified.
func getSignature(addr va.Address, filename string, parseCert bool) *signature.Signature {
	sign := signature.GetSignatures().GetSignature(addr.Uint64())
	if sign != nil {
		if parseCert {
			err := sign.ParseCertificate()
			if err != nil {
				certErrors.Add(1)
			}
		}
		return sign
	}

	var err error
	sign = &signature.Signature{Filename: filename}
	sign.Type, sign.Level, err = sign.Check()
	if err != nil {
		signatureErrors.Add(1)
	}

	if sign.IsSigned() {
		sign.Verify()
	}

	if parseCert {
		err = sign.ParseCertificate()
		if err != nil {
			certErrors.Add(1)
		}
	}

	signature.GetSignatures().PutSignature(addr.Uint64(), sign)

	return sign
}

// framePID returns the pid associated with the stack frame.
func framePID(e *event.Event) uint32 {
	if !e.Callstack.IsEmpty() && e.Callstack.FrameAt(0).PID != 0 {
		return e.Callstack.FrameAt(0).PID
	}
	return e.PID
}

// CompareSeqLink returns true if any value
// in the sequence link slice equals to the
// given LHS value.
func CompareSeqLink(lhs any, rhs []any) bool {
	if lhs == nil || rhs == nil {
		return false
	}
	for _, v := range rhs {
		if compareSeqLink(lhs, v) {
			return true
		}
	}
	return false
}

// CompareSeqLinks returns true any LHS sequence
// link values equal to the RHS sequence link values.
func CompareSeqLinks(lhs []any, rhs []any) bool {
	if lhs == nil || rhs == nil {
		return false
	}
	for _, v1 := range lhs {
		for _, v2 := range rhs {
			if compareSeqLink(v1, v2) {
				return true
			}
		}
	}
	return false
}

func compareSeqLink(lhs any, rhs any) bool {
	if lhs == nil || rhs == nil {
		return false
	}

	switch v := lhs.(type) {
	case string:
		s, ok := rhs.(string)
		if !ok {
			return false
		}
		return strings.EqualFold(v, s)
	case uint8:
		n, ok := rhs.(uint8)
		if !ok {
			return false
		}
		return v == n
	case uint16:
		n, ok := rhs.(uint16)
		if !ok {
			return false
		}
		return v == n
	case uint32:
		n, ok := rhs.(uint32)
		if !ok {
			return false
		}
		return v == n
	case uint64:
		n, ok := rhs.(uint64)
		if !ok {
			return false
		}
		if v == n {
			return true
		}
	case int:
		n, ok := rhs.(int)
		if !ok {
			return false
		}
		return v == n
	case uint:
		n, ok := rhs.(uint)
		if !ok {
			return false
		}
		return v == n
	case net.IP:
		ip, ok := rhs.(net.IP)
		if !ok {
			return false
		}
		return v.Equal(ip)
	}
	return false
}

// hashFields computes the hash of all field values.
func hashFields(values []any) string {
	buf := make([]byte, 0)
	for _, v := range values {
		switch val := v.(type) {
		case uint8:
			buf = append(buf, val)
		case uint16:
			buf = append(buf, bytes.WriteUint16(val)...)
		case uint32:
			buf = append(buf, bytes.WriteUint32(val)...)
		case uint64:
			buf = append(buf, bytes.WriteUint64(val)...)
		case int8:
			buf = append(buf, byte(val))
		case int16:
			buf = append(buf, bytes.WriteUint16(uint16(val))...)
		case int32:
			buf = append(buf, bytes.WriteUint32(uint32(val))...)
		case int64:
			buf = append(buf, bytes.WriteUint64(uint64(val))...)
		case int:
			buf = append(buf, bytes.WriteUint64(uint64(val))...)
		case uint:
			buf = append(buf, bytes.WriteUint64(uint64(val))...)
		case string:
			buf = append(buf, val...)
		case net.IP:
			buf = append(buf, val...)
		}
	}
	return hex.EncodeToString(buf)
}

func joinsEqual(joins []bool) bool {
	for _, j := range joins {
		if !j {
			return false
		}
	}
	return true
}
