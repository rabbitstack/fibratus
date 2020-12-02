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

package object

import (
	"fmt"
	"github.com/rabbitstack/fibratus/pkg/syscall/handle"
	"unsafe"
)

// AlpcInformationClass defines the type for the ALPC information class values.
type AlpcInformationClass uint8

const (
	// AlpcBasicPortInfo obtains basic ALPC port information
	AlpcBasicPortInfo AlpcInformationClass = iota
)

var ntAlpcQueryInformation = nt.NewProc("NtAlpcQueryInformation")

// GetAlpcInformation gets specified information for the ALPC handle.
func GetAlpcInformation(handle handle.Handle, klass AlpcInformationClass, buf []byte) error {
	status, _, _ := ntAlpcQueryInformation.Call(
		uintptr(handle),
		uintptr(klass),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
	)
	if status != 0 {
		return fmt.Errorf("NtAlpcQueryInformation failed with status code 0x%X", status)
	}
	return nil
}
