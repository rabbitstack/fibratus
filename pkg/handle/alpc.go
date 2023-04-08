//go:build windows
// +build windows

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

package handle

import (
	htypes "github.com/rabbitstack/fibratus/pkg/handle/types"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"golang.org/x/sys/windows"
	"unsafe"
)

// GetAlpcPort get ALPC port information for the specified ALPC port handle.
func GetAlpcPort(handle windows.Handle) (*htypes.AlpcPortInfo, error) {
	b := make([]byte, 16)
	err := sys.NtAlpcQueryInformation(handle, sys.AlpcBasicPortInformationClass, unsafe.Pointer(&b[0]), uint32(len(b)), nil)
	if err != nil {
		return nil, err
	}
	return (*htypes.AlpcPortInfo)(unsafe.Pointer(&b[0])), nil
}
