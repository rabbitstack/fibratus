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

package zsyscall

import (
	"golang.org/x/sys/windows"
	"syscall"
)

var drives = []string{
	"A",
	"B",
	"C",
	"D",
	"E",
	"F",
	"G",
	"H",
	"I",
	"J",
	"K",
	"L",
	"M",
	"N",
	"O",
	"P",
	"Q",
	"R",
	"S",
	"T",
	"U",
	"V",
	"W",
	"X",
	"Y",
	"Z"}

// GetLogicalDrives returns available device drive letters in the system.
func GetLogicalDrives() []string {
	bitmask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	devs := make([]string, 0)
	for _, drive := range drives {
		if bitmask&1 == 1 {
			devs = append(devs, drive+":")
		}
		bitmask >>= 1
	}
	return devs
}

// QueryDosDevice translates the DOS device name to hard disk drive letter.
func QueryDosDevice(drive string) (string, error) {
	dev := make([]uint16, syscall.MAX_PATH)
	_, err := windows.QueryDosDevice(windows.StringToUTF16Ptr(drive), &dev[0], windows.MAX_PATH)
	if err != nil {
		return "", err
	}
	return windows.UTF16ToString(dev), nil
}

func PathIsDirectory(path string) bool {
	return pathIsDirectory(windows.StringToUTF16Ptr(path))
}
