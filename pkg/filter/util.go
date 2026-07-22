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
	"net"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/util/bytes"
)

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
