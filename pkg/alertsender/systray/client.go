//go:build windows

/*
 * Copyright 2026 by Nedim Sabic Sabic
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

package systray

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

const (
	// pipeClientAccess is FILE_GENERIC_READ. Clients only ever read from the pipe, so
	// they don't ask for (and are not granted) write access, which also means they
	// can't create additional pipe instances.
	pipeClientAccess = 0x00120089
	// securitySQOSPresent and securityAnonymous open the pipe at the anonymous
	// impersonation level, so the server can't impersonate the client.
	securitySQOSPresent = 0x00100000
	securityAnonymous   = 0x00000000
)

// ErrUntrustedServer is returned by Dial when the systray pipe exists but it
// isn't owned by LocalSystem or the Administrators group, which is how a process
// squatting on the pipe name would show up.
var ErrUntrustedServer = errors.New("the systray pipe is not owned by a trusted principal")

// Client is the receiving end of the systray pipe. It is used by the
// `fibratus systray` helper that runs inside an interactive user session.
type Client struct {
	f  *os.File
	sc *bufio.Scanner
}

// Dial connects to the systray pipe served by the Fibratus service or the foreground
// process and verifies the identity of the server before any data is read from it.
func Dial() (*Client, error) {
	name, err := windows.UTF16PtrFromString(systrayPipe)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(
		name,
		pipeClientAccess,
		0,
		nil,
		windows.OPEN_EXISTING,
		securitySQOSPresent|securityAnonymous,
		0,
	)
	if err != nil {
		return nil, err
	}
	if err := verifyServer(h); err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	return newClient(os.NewFile(uintptr(h), systrayPipe)), nil
}

func newClient(f *os.File) *Client {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), maxMsgSize)
	return &Client{f: f, sc: sc}
}

// Recv blocks until the next message arrives. It returns io.EOF when the
// server closes the pipe.
func (c *Client) Recv() (Msg, error) {
	var m Msg
	if !c.sc.Scan() {
		if err := c.sc.Err(); err != nil {
			return m, err
		}
		return m, io.EOF
	}
	if err := json.Unmarshal(c.sc.Bytes(), &m); err != nil {
		return m, fmt.Errorf("malformed systray message: %w", err)
	}
	return m, nil
}

// Close closes the pipe handle.
func (c *Client) Close() error {
	return c.f.Close()
}

// verifyServer checks that the pipe is owned by LocalSystem or by the
// Administrators group. Pipe names are global and first come, first served,
// so without this check any local process could stand in for the service
// and receive (or withhold) the alerts.
func verifyServer(h windows.Handle) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("unable to query the owner of the %s pipe: %w", systrayPipe, err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("unable to get the owner of the %s pipe: %w", systrayPipe, err)
	}
	if owner == nil {
		return fmt.Errorf("%w: the %s pipe has no owner", ErrUntrustedServer, systrayPipe)
	}
	for _, typ := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(typ)
		if err != nil {
			continue
		}
		if owner.Equals(sid) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s is owned by %s", ErrUntrustedServer, systrayPipe, owner)
}
