//go:build linux

/*
 * Copyright 2026 by Mostafa Moradian
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
)

// hostname is the current host name or FQDN
var hostname string

// hostnameErrors exposes host/fqdn resolution errors
var hostnameErrors = expvar.NewMap("hostname.errors")

// Get returns the host name of the machine.
func Get() string {
	if hostname != "" {
		return hostname
	}
	var err error
	hostname, err = os.Hostname()
	if err != nil {
		hostnameErrors.Add(err.Error(), 1)
	}
	if hostname == "" {
		ip := localIP()
		if ip != "" {
			hostname = ip
		} else {
			hostname = "unknown"
		}
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
			if ip != nil && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return ""
}
