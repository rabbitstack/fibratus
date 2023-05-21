/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package sys

import (
	"errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

// ErrNoSession signals that the active Windows Terminal Session is not available
var ErrNoSession = errors.New("no active Windows Terminal Session")

// WTSUserName is the WTS class that returns a null-terminated string
// containing the name of the user associated with the active session.
const WTSUserName = 5

// WTS contains information about the current Windows Terminal Session.
type WTS struct {
	sessionID uint32
}

// LookupActiveWTS finds the active Windows Terminal Session.
func LookupActiveWTS() (*WTS, error) {
	var sess *windows.WTS_SESSION_INFO
	var count uint32
	err := windows.WTSEnumerateSessions(0, 0, 1, &sess, &count)
	if err != nil {
		return nil, err
	}
	sessions := unsafe.Slice(sess, count)
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sess)))
	for _, ses := range sessions {
		if ses.State == windows.WTSActive || ses.State == windows.WTSConnected {
			wts := &WTS{sessionID: ses.SessionID}
			return wts, nil
		}
	}
	return nil, ErrNoSession
}

// Username returns the name of the currently logged-on user.
func (w *WTS) Username() (string, error) {
	var size uint32
	var user *uint16
	err := WTSQuerySessionInformationA(0, w.sessionID, WTSUserName, &user, &size)
	if err != nil {
		return "", err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(user)))
	return windows.UTF16PtrToString(user), nil
}

// SID returns the SID (Security Identifier) of the currently logged-on user.
func (w *WTS) SID() (*windows.SID, error) {
	username, err := w.Username()
	if err != nil {
		return nil, err
	}
	sid, _, _, err := windows.LookupSID("", username)
	if err != nil {
		return nil, err
	}
	return sid, nil
}
