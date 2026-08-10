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
	NTStatus                   = "status"
	ProcessObject              = "kproc"
	Callstack                  = "callstack"
	CallstackTimestamp         = "callstack_timestamp"
	ProcessRealParentID        = "real_ppid"
	UserSID                    = "sid"
	Domain                     = "domain"
	DTB                        = "directory_table_base"
	ProcessTokenIntegrityLevel = "token_integrity_level"
	ProcessTokenElevationType  = "token_elevation_type"
	ProcessTokenIsElevated     = "token_is_elevated"
	DesiredAccess              = "desired_access"
	BasePrio                   = "base_prio"
	IOPrio                     = "io_prio"
	PagePrio                   = "page_prio"
	KstackBase                 = "kstack"
	KstackLimit                = "kstack_limit"
	UstackBase                 = "ustack"
	UstackLimit                = "ustack_limit"
	StartAddress               = "start_address"
	StartAddressSymbol         = "start_address_symbol"
	StartAddressModule         = "start_address_module"
	TEB                        = "teb"
	FileCreateOptions          = "create_options"
	FileOperation              = "create_disposition"
	FileShareMask              = "share_mask"
	FileAttributes             = "attributes"
	FileInfoClass              = "class"
	FileIrpPtr                 = "irp"
	FileIsDLL                  = "is_dll"
	FileIsDriver               = "is_driver"
	FileIsDotnet               = "is_dotnet"
	RegKeyHandle               = "key_handle"
	RegKCB                     = "kcb"
	RegPath                    = "key_path"
	RegValue                   = "value"
	RegValueType               = "value_type"
	RegData                    = "data"
	ModuleCheckSum             = "checksum"
	ModuleTimeDateStamp        = "timedate_stamp"
	ModuleDefaultBase          = "default_address"
	ModuleSignatureLevel       = "signature_level"
	ModuleSignatureType        = "signature_type"
	ModuleCertSubject          = "cert_subject"
	ModuleCertIssuer           = "cert_issuer"
	ModuleCertSerial           = "cert_serial"
	ModuleCertNotBefore        = "cert_not_before"
	ModuleCertNotAfter         = "cert_not_after"
	HandleID                   = "handle_id"
	HandleSourceID             = "handle_source_id"
	HandleObject               = "handle_object"
	HandleObjectName           = "handle_name"
	HandleObjectTypeID         = "type_id"
	ThreadpoolPoolID           = "pool_id"
	ThreadpoolTaskID           = "task_id"
	ThreadpoolCallback         = "callback"
	ThreadpoolCallbackSymbol   = "callback_symbol"
	ThreadpoolCallbackModule   = "callback_module"
	ThreadpoolContext          = "context"
	ThreadpoolContextRip       = "context_rip"
	ThreadpoolContextRipSymbol = "context_rip_symbol"
	ThreadpoolContextRipModule = "context_rip_module"
	ThreadpoolSubprocessTag    = "subprocess_tag"
	ThreadpoolTimerDuetime     = "duetime"
	ThreadpoolTimerSubqueue    = "subqueue"
	ThreadpoolTimer            = "timer"
	ThreadpoolTimerPeriod      = "period"
	ThreadpoolTimerWindow      = "window"
	ThreadpoolTimerAbsolute    = "absolute"
)
