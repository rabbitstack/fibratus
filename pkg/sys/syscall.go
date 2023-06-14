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

// Native API Functions
//sys NtQueryObject(handle windows.Handle, objectInfoClass int32, objInfo unsafe.Pointer, objInfoLen uint32, retLen *uint32) (ntstatus error) = ntdll.NtQueryObject
//sys NtQueryMutant(handle windows.Handle, mutantInfoClass int32, mutantInfo unsafe.Pointer, mutantInfoLen uint32, retLen *uint32) (ntstatus error) = ntdll.NtQueryMutant
//sys NtAlpcQueryInformation(handle windows.Handle, alpcInfoClass int32, alpcInfo unsafe.Pointer, alpcInfoLen uint32, retLen *uint32) (ntstatus error) = ntdll.NtAlpcQueryInformation
//sys NtQueryVolumeInformationFile(handle windows.Handle, ioStatusBlock *windows.IO_STATUS_BLOCK, fsInfo uintptr, retLen uint32, fsInfoClass int32) (ntstatus error) = ntdll.NtQueryVolumeInformationFile
//sys RtlNtStatusToDosError(status uint32) (code uint32) = ntdll.RtlNtStatusToDosError
//sys NtCreateSection(section *windows.Handle, desiredAccess uint32, objectAttributes uintptr, maxSize uintptr, protection uint32, allocation uint32, file windows.Handle) (ntstatus error) = ntdll.NtCreateSection
//sys NtMapViewOfSection(section windows.Handle, process windows.Handle, sectionBase uintptr, zeroBits uintptr, commitSize uintptr, offset uintptr, size uintptr, inherit uint32, allocation uint32, protect uint32) (ntstatus error) = ntdll.NtMapViewOfSection
//sys NtUnmapViewOfSection(process windows.Handle, addr uintptr) (ntstatus error) = ntdll.NtUnmapViewOfSection

// Thread Functions
//sys GetProcessIdOfThread(handle windows.Handle) (pid uint32) = kernel32.GetProcessIdOfThread
//sys CreateThread(attributes *windows.SecurityAttributes, stackSize uint, startAddress uintptr, param uintptr, creationFlags uint32, threadID *uint32) (handle windows.Handle) = kernel32.CreateThread
//sys TerminateThread(handle windows.Handle, exitCode uint32) (err error) = kernel32.TerminateThread

// File Functions
//sys pathIsDirectory(path *uint16) (isDirectory bool) = shlwapi.PathIsDirectoryW

// Device Functions
//sys EnumDeviceDrivers(imageBase uintptr, size uint32, needed *uint32) (err error) = psapi.EnumDeviceDrivers
//sys GetDeviceDriverFileName(imageBase uintptr, filename *uint16, size uint32) (n uint32) = psapi.GetDeviceDriverFileNameW

// Windows Terminal Server Functions
//sys WTSQuerySessionInformationA(handle windows.Handle, sessionID uint32, klass uint8, buf **uint16, size *uint32) (err error) = wtsapi32.WTSQuerySessionInformationW

// Windows Trust Functions
//sys WinVerifyTrust(handle windows.Handle, action *windows.GUID, data *WintrustData) (ret uint32, err error) [failretval!=0] = wintrust.WinVerifyTrust
//sys CryptCatalogAdminAcquireContext(handle *windows.Handle, subsystem *windows.GUID, hashAlgorithm *uint16, hashPolicy uintptr, flags uint32) (err error) = wintrust.CryptCATAdminAcquireContext2
//sys CryptCatalogAdminReleaseContext(handle windows.Handle, flags int32) (ok bool) = wintrust.CryptCATAdminReleaseContext
//sys CryptCatalogAdminCalcHashFromFileHandle(handle windows.Handle, fd uintptr, size *uint32, hash uintptr, flags uint32) (err error) = wintrust.CryptCATAdminCalcHashFromFileHandle2
//sys CryptCatalogAdminEnumCatalogFromHash(handle windows.Handle, hash uintptr, size uint32, flags uint32, prevCatalog *windows.Handle) (catalog windows.Handle) = wintrust.CryptCATAdminEnumCatalogFromHash
//sys CryptCatalogInfoFromContext(handle windows.Handle, catalog *CatalogInfo, flags uint32) (err error) = wintrust.CryptCATCatalogInfoFromContext
//sys CryptCatalogAdminReleaseCatalogContext(handle windows.Handle, info windows.Handle, flags uint32) (err error) = wintrust.CryptCATAdminReleaseCatalogContext

// Process Status API Functions
//sys GetMappedFileName(handle windows.Handle, addr uintptr, filename *uint16, size uint32) (n uint32) = psapi.GetMappedFileNameW
