/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package ip

import (
	"net"
	"syscall"
	"unsafe"
)

var (
	nt = syscall.NewLazyDLL("ntdll.dll")

	// rtlIpv6AddressToString is the procedure for `RtlIpv6AddressToStringW` API call.
	rtlIpv6AddressToString = nt.NewProc("RtlIpv6AddressToStringW")
)

// ToIPv4 accepts an integer IP address in network byte order and returns an IP-typed address.
func ToIPv4(ip uint32) net.IP {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// ToIPv6 converts the buffer with IPv6 address in network byte order to an IP-typed address.
func ToIPv6(buffer []byte) net.IP {
	ipv6 := make([]uint16, 46)
	if rtlIpv6AddressToString != nil {
		_, _, _ = rtlIpv6AddressToString.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&ipv6[0])))
	}
	return net.ParseIP(syscall.UTF16ToString(ipv6))
}
