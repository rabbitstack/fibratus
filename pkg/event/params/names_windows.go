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

package params

const (
	// NTStatus identifies the NTSTATUS value.
	NTStatus = "status"
	// ProcessObject represents the address of the process object in the kernel.
	ProcessObject = "kproc"
	// Callstack represents the thread call stack.
	Callstack = "callstack"
	// CallstackTimestamp identifies the call stack timestamp.
	CallstackTimestamp = "callstack_timestamp"
	// ProcessRealParentID represents the real parent process identifier.
	ProcessRealParentID = "real_ppid"
	// UserSID is the security identifier associated with the process token.
	UserSID = "sid"
	// Domain represents the domain under which the event was generated.
	Domain = "domain"
	// DTB denotes the address of the process directory table.
	DTB = "directory_table_base"
	// ProcessTokenIntegrityLevel denotes the process integrity level.
	ProcessTokenIntegrityLevel = "token_integrity_level"
	// ProcessTokenElevationType designates the process token elevation type.
	ProcessTokenElevationType = "token_elevation_type"
	// ProcessTokenIsElevated designates whether the process token is elevated.
	ProcessTokenIsElevated = "token_is_elevated"
	// DesiredAccess denotes the access rights for a kernel object.
	DesiredAccess = "desired_access"
	// BasePrio is the thread base priority assigned by the scheduler.
	BasePrio = "base_prio"
	// IOPrio indicates the thread I/O priority.
	IOPrio = "io_prio"
	// PagePrio denotes the page priority.
	PagePrio = "page_prio"
	// KstackBase is the start address of the kernel-space stack.
	KstackBase = "kstack"
	// KstackLimit is the end address of the kernel-space stack.
	KstackLimit = "kstack_limit"
	// UstackBase is the start address of the user-space stack.
	UstackBase = "ustack"
	// UstackLimit is the end address of the user-space stack.
	UstackLimit = "ustack_limit"
	// StartAddress is the thread start address.
	StartAddress = "start_address"
	// StartAddressSymbol is the symbol associated with the thread start address.
	StartAddressSymbol = "start_address_symbol"
	// StartAddressModule is the module containing the thread start address.
	StartAddressModule = "start_address_module"
	// TEB is the address of the Thread Environment Block.
	TEB = "teb"
	// FileCreateOptions represents options passed to NtCreateFile.
	FileCreateOptions = "create_options"
	// FileOperation represents the file create disposition.
	FileOperation = "create_disposition"
	// FileShareMask represents the file share access mask.
	FileShareMask = "share_mask"
	// FileAttributes represents file attribute values.
	FileAttributes = "attributes"
	// FileInfoClass represents the file information class.
	FileInfoClass = "class"
	// FileIrpPtr represents the I/O request packet identifier.
	FileIrpPtr = "irp"
	// FileIsDLL indicates whether the file is a DLL.
	FileIsDLL = "is_dll"
	// FileIsDriver indicates whether the file is a driver.
	FileIsDriver = "is_driver"
	// FileIsDotnet indicates whether the file is a .NET assembly.
	FileIsDotnet = "is_dotnet"
	// RegKeyHandle identifies the registry key handle.
	RegKeyHandle = "key_handle"
	// RegKCB identifies the registry key control block.
	RegKCB = "kcb"
	// RegPath represents the fully qualified registry key path.
	RegPath = "key_path"
	// RegValue identifies the registry value.
	RegValue = "value"
	// RegValueType identifies the registry value type.
	RegValueType = "value_type"
	// RegData stores the captured registry data.
	RegData = "data"
	// ModuleCheckSum is the module checksum.
	ModuleCheckSum = "checksum"
	// ModuleTimeDateStamp is the module timestamp.
	ModuleTimeDateStamp = "timedate_stamp"
	// ModuleDefaultBase is the module's default base address.
	ModuleDefaultBase = "default_address"
	// ModuleSignatureLevel is the loaded module signature level.
	ModuleSignatureLevel = "signature_level"
	// ModuleSignatureType is the loaded module signature type.
	ModuleSignatureType = "signature_type"
	// ModuleCertSubject is the module certificate subject.
	ModuleCertSubject = "cert_subject"
	// ModuleCertIssuer is the module certificate issuer.
	ModuleCertIssuer = "cert_issuer"
	// ModuleCertSerial is the module certificate serial number.
	ModuleCertSerial = "cert_serial"
	// ModuleCertNotBefore is the beginning of the module certificate validity period.
	ModuleCertNotBefore = "cert_not_before"
	// ModuleCertNotAfter is the end of the module certificate validity period.
	ModuleCertNotAfter = "cert_not_after"
	// HandleID identifies the handle.
	HandleID = "handle_id"
	// HandleSourceID identifies the source handle.
	HandleSourceID = "handle_source_id"
	// HandleObject identifies the kernel object backing the handle.
	HandleObject = "handle_object"
	// HandleObjectName is the handle object name.
	HandleObjectName = "handle_name"
	// HandleObjectTypeID is the handle object type identifier.
	HandleObjectTypeID = "type_id"
	// ThreadpoolPoolID identifies the thread pool.
	ThreadpoolPoolID = "pool_id"
	// ThreadpoolTaskID identifies the thread pool task.
	ThreadpoolTaskID = "task_id"
	// ThreadpoolCallback is the thread pool callback address.
	ThreadpoolCallback = "callback"
	// ThreadpoolCallbackSymbol is the thread pool callback symbol.
	ThreadpoolCallbackSymbol = "callback_symbol"
	// ThreadpoolCallbackModule is the module containing the callback.
	ThreadpoolCallbackModule = "callback_module"
	// ThreadpoolContext is the thread pool callback context.
	ThreadpoolContext = "context"
	// ThreadpoolContextRip is the instruction pointer in the callback context.
	ThreadpoolContextRip = "context_rip"
	// ThreadpoolContextRipSymbol is the symbol for the context instruction pointer.
	ThreadpoolContextRipSymbol = "context_rip_symbol"
	// ThreadpoolContextRipModule is the module containing the context instruction pointer.
	ThreadpoolContextRipModule = "context_rip_module"
	// ThreadpoolSubprocessTag is the thread pool subprocess tag.
	ThreadpoolSubprocessTag = "subprocess_tag"
	// ThreadpoolTimerDuetime is the timer due time.
	ThreadpoolTimerDuetime = "duetime"
	// ThreadpoolTimerSubqueue is the timer subqueue.
	ThreadpoolTimerSubqueue = "subqueue"
	// ThreadpoolTimer identifies the timer.
	ThreadpoolTimer = "timer"
	// ThreadpoolTimerPeriod is the timer period.
	ThreadpoolTimerPeriod = "period"
	// ThreadpoolTimerWindow is the timer window.
	ThreadpoolTimerWindow = "window"
	// ThreadpoolTimerAbsolute indicates whether the timer due time is absolute.
	ThreadpoolTimerAbsolute = "absolute"
)
