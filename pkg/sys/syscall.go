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

//go:generate go run golang.org/x/sys/windows/mkwinsyscall -output zsyscall_windows.go syscall.go

//sys NtQueryObject(handle windows.Handle, objectInfoClass int32, objInfo unsafe.Pointer, objInfoLen uint32, retLen *uint32) (ntstatus error) = ntdll.NtQueryObject
//sys NtQueryMutant(handle windows.Handle, mutantInfoClass int32, mutantInfo unsafe.Pointer, mutantInfoLen uint32, retLen *uint32) (ntstatus error) = ntdll.NtQueryMutant
//sys NtAlpcQueryInformation(handle windows.Handle, alpcInfoClass int32, alpcInfo unsafe.Pointer, alpcInfoLen uint32, retLen *uint32) (ntstatus error) = ntdll.NtAlpcQueryInformation
//sys NtQueryVolumeInformationFile(handle windows.Handle, ioStatusBlock *windows.IO_STATUS_BLOCK, fsInfo uintptr, retLen uint32, fsInfoClass int32) (ntstatus error) = ntdll.NtQueryVolumeInformationFile
//sys GetProcessIdOfThread(handle windows.Handle) (pid uint32) = kernel32.GetProcessIdOfThread
//sys pathIsDirectory(path *uint16) (isDirectory bool) = shlwapi.PathIsDirectoryW
//sys RtlNtStatusToDosError(status uint32) (code uint32) = ntdll.RtlNtStatusToDosError
//sys CreateThread(attributes *windows.SecurityAttributes, stackSize uint, startAddress uintptr, param uintptr, creationFlags uint32, threadID *uint32) (handle windows.Handle) = kernel32.CreateThread
//sys TerminateThread(handle windows.Handle, exitCode uint32) (err error) = kernel32.TerminateThread
//sys EnumDeviceDrivers(imageBase uintptr, size uint32, needed *uint32) (err error) = psapi.EnumDeviceDrivers
//sys GetDeviceDriverFileName(imageBase uintptr, filename *uint16, size uint32) (n uint32) = psapi.GetDeviceDriverFileNameW
