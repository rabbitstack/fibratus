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

package ebpf

import (
	"encoding/binary"
	"net"

	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/event/params"
	"golang.org/x/sys/unix"
)

func appendSockParams(evt *event.Event, r rawEvent) {
	evt.Params.Append(params.FD, params.Int64, int64(r.Arg0))
	if r.Type == uint32(event.Accept) && r.Retval >= 0 {
		evt.Params.Append(params.NewFD, params.Int64, r.Retval)
	}
	if r.Flags != 0 {
		evt.Params.Append(params.SockFlags, params.Uint64, r.Flags)
	}

	family, ip, port, unixPath := parseSockaddr(r.Aux[:])
	evt.Params.Append(params.SockFamily, params.Uint16, family)
	if unixPath != "" {
		evt.Params.Append(params.SockPath, params.Path, unixPath)
		return
	}
	if ip == nil {
		return
	}
	ipParam := params.IPv4
	if ip.To4() == nil {
		ipParam = params.IPv6
	}
	if r.Type == uint32(event.Connect) {
		evt.Params.Append(params.NetDIP, ipParam, ip)
		evt.Params.Append(params.NetDport, params.Port, port)
		return
	}
	evt.Params.Append(params.NetSIP, ipParam, ip)
	evt.Params.Append(params.NetSport, params.Port, port)
}

func parseSockaddr(b []byte) (family uint16, ip net.IP, port uint16, unixPath string) {
	if len(b) < 2 {
		return 0, nil, 0, ""
	}
	family = binary.LittleEndian.Uint16(b[0:2])
	switch family {
	case unix.AF_INET:
		if len(b) >= 8 {
			port = binary.BigEndian.Uint16(b[2:4])
			ip = net.IPv4(b[4], b[5], b[6], b[7]).To4()
		}
	case unix.AF_INET6:
		if len(b) >= 24 {
			port = binary.BigEndian.Uint16(b[2:4])
			ip = net.IP(append([]byte(nil), b[8:24]...))
		}
	case unix.AF_UNIX:
		if len(b) > 2 {
			unixPath = cString(b[2:])
		}
	}
	return family, ip, port, unixPath
}
