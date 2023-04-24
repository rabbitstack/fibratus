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
	"golang.org/x/sys/windows"
	"unsafe"
)

// WTSUserName is the WTS class that returns a null-terminated string
// that contains the name of the user associated with the session
const WTSUserName = 5

// GetLoggedSID returns the SID for the currently logged-in user.
func GetLoggedSID() (*windows.SID, error) {
	user, err := GetLoggedUser()
	if err != nil {
		return nil, err
	}
	sid, _, _, err := windows.LookupSID("", user)
	if err != nil {
		return nil, err
	}
	return sid, nil
}

// GetLoggedUser obtains the currently logged-in username.
func GetLoggedUser() (string, error) {
	sessionID, err := getActiveSessionID()
	if err != nil {
		return "", err
	}
	var size uint32
	var user *uint16
	err = WTSQuerySessionInformationA(0, sessionID, WTSUserName, &user, &size)
	if err != nil {
		return "", err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(user)))
	return windows.UTF16PtrToString(user), nil
}

func getActiveSessionID() (uint32, error) {
	var sess *windows.WTS_SESSION_INFO
	var count uint32
	var sessionID uint32
	err := windows.WTSEnumerateSessions(0, 0, 1, &sess, &count)
	if err != nil {
		return 0, err
	}
	sessions := unsafe.Slice(sess, count)
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sess)))
	for _, ses := range sessions {
		if ses.State == windows.WTSActive || ses.State == windows.WTSConnected {
			sessionID = ses.SessionID
			break
		}
	}
	return sessionID, nil
}
