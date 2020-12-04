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

package hostname

import (
	"expvar"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// hostname is the current host name or FQDN
var hostname string

// hostnameErrors exposes host/fqdn resolution errors
var hostnameErrors = expvar.NewMap("hostname.errors")

const computerNamePhysicalDNSFullyQualified = 7

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	getComputerName = kernel32.NewProc("GetComputerNameExW")
)

// Get returns the host name or the FQDN of the machine.
func Get() string {
	if hostname != "" {
		return hostname
	}
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		hostnameErrors.Add(err.Error(), 1)
	}

	// get the Fully Qualified Domain Name (FQDN) of this machine
	maxComputerLength := 1024
	buf := make([]uint16, maxComputerLength)
	errno, _, err := getComputerName.Call(
		uintptr(computerNamePhysicalDNSFullyQualified),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&maxComputerLength)))
	if errno == 0 {
		// we couldn't get the hostname neither the FQDN
		// so we try to fetch the local IP and use as hostname
		if hostname == "" {
			ip := localIP()
			if ip != "" {
				hostname = ip
			} else {
				hostname = "unknown"
			}
		}
		hostnameErrors.Add(err.Error(), 1)
		return hostname
	}

	fqdn := syscall.UTF16ToString(buf)
	if fqdn != "" {
		hostname = fqdn
	}

	return hostname
}

// localIP returns the first non-loopback interface IP address.
func localIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return ""
}
