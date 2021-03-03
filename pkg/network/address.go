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

package network

import "net"

// Address is the comparable type-alias for the IP v4/v6 addresses
type Address [16]byte

// ToIP converts the address to net.IP type.
func (addr Address) ToIP() net.IP {
	return net.IP(addr[:])
}

// ToIPString converts the address to IP string representation.
func (addr Address) ToIPString() string {
	return addr.ToIP().String()
}

// AddressFromIP constructs the address from the IP address.
func AddressFromIP(ip net.IP) Address {
	var addr Address
	copy(addr[:], ip)
	return addr
}
