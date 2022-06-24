/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package kevent

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rabbitstack/fibratus/pkg/fs"
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/network"
	"github.com/rabbitstack/fibratus/pkg/syscall/security"
	"github.com/rabbitstack/fibratus/pkg/util/ip"
)

// NewKparam creates a new event parameter. Since the parameter type is already categorized,
// we can coerce the value to the appropriate representation (e.g. hex, IP address, user security identifier, etc.)
func NewKparam(name string, typ kparams.Type, value kparams.Value) *Kparam {
	var v kparams.Value
	switch typ {
	case kparams.HexInt8, kparams.HexInt16, kparams.HexInt32, kparams.HexInt64:
		v = kparams.NewHex(value)

	case kparams.IPv4:
		v = ip.ToIPv4(value.(uint32))

	case kparams.IPv6:
		v = ip.ToIPv6(value.([]byte))

	case kparams.Port:
		v = syscall.Ntohs(value.(uint16))

	case kparams.SID:
		account, domain := security.LookupAccount(value.([]byte), false)
		if account != "" || domain != "" {
			v = joinSID(account, domain)
		}

	case kparams.WbemSID:
		account, domain := security.LookupAccount(value.([]byte), true)
		if account != "" || domain != "" {
			v = joinSID(account, domain)
		}

	default:
		v = value
	}

	kparam := kparamPool.Get().(*Kparam)
	*kparam = Kparam{Name: name, Type: typ, Value: v}

	return kparam
}

// String returns the string representation of the parameter value.
func (k Kparam) String() string {
	if k.Value == nil {
		return ""
	}
	switch k.Type {
	case kparams.UnicodeString, kparams.AnsiString, kparams.SID, kparams.WbemSID:
		return k.Value.(string)
	case kparams.HexInt32, kparams.HexInt64, kparams.HexInt16, kparams.HexInt8:
		return string(k.Value.(kparams.Hex))
	case kparams.Int8:
		return strconv.Itoa(int(k.Value.(int8)))
	case kparams.Uint8:
		return strconv.Itoa(int(k.Value.(uint8)))
	case kparams.Int16:
		return strconv.Itoa(int(k.Value.(int16)))
	case kparams.Uint16, kparams.Port:
		return strconv.Itoa(int(k.Value.(uint16)))
	case kparams.Uint32, kparams.PID, kparams.TID:
		return strconv.Itoa(int(k.Value.(uint32)))
	case kparams.Int32:
		return strconv.Itoa(int(k.Value.(int32)))
	case kparams.Uint64:
		return strconv.FormatUint(k.Value.(uint64), 10)
	case kparams.Int64:
		return strconv.Itoa(int(k.Value.(int64)))
	case kparams.IPv4, kparams.IPv6:
		return k.Value.(net.IP).String()
	case kparams.Bool:
		return strconv.FormatBool(k.Value.(bool))
	case kparams.Float:
		return strconv.FormatFloat(float64(k.Value.(float32)), 'f', 6, 32)
	case kparams.Double:
		return strconv.FormatFloat(k.Value.(float64), 'f', 6, 64)
	case kparams.Time:
		return k.Value.(time.Time).String()
	case kparams.Enum:
		switch typ := k.Value.(type) {
		case fs.FileShareMode:
			return typ.String()
		case network.L4Proto:
			return typ.String()
		case fs.FileDisposition:
			return typ.String()
		default:
			return fmt.Sprintf("%v", k.Value)
		}
	case kparams.Slice:
		switch slice := k.Value.(type) {
		case []string:
			return strings.Join(slice, ",")
		case []fs.FileAttr:
			attrs := make([]string, 0, len(slice))
			for _, s := range slice {
				attrs = append(attrs, s.String())
			}
			return strings.Join(attrs, ",")
		default:
			return fmt.Sprintf("%v", slice)
		}
	default:
		return fmt.Sprintf("%v", k.Value)
	}
}

func joinSID(account, domain string) string { return fmt.Sprintf("%s\\%s", domain, account) }
