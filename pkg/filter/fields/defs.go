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

package fields

import (
	"strings"
	"unicode"

	"github.com/rabbitstack/fibratus/pkg/event/params"
)

// Field represents the type alias for the field
type Field string

const (
	// PsPid represents the process id field
	PsPid Field = "ps.pid"
	// PsPpid represents the parent process id field
	PsPpid Field = "ps.ppid"
	// PsName represents the process name field
	PsName Field = "ps.name"
	// PsComm represents the process command line field. Deprecated.
	PsComm Field = "ps.comm"
	// PsCmdline represents the process command line field
	PsCmdline Field = "ps.cmdline"
	// PsExe represents the process image path field
	PsExe Field = "ps.exe"
	// PsArgs represents the process command line arguments
	PsArgs Field = "ps.args"
	// PsCwd represents the process current working directory
	PsCwd Field = "ps.cwd"
	// PsSID represents the process security identifier
	PsSID Field = "ps.sid"
	// PsDomain represents the process domain field
	PsDomain Field = "ps.domain"
	// PsUsername represents the process username field
	PsUsername Field = "ps.username"
	// PsSessionID represents the session id bound to the process
	PsSessionID Field = "ps.sessionid"
	// PsEnvs represents the process environment variables
	PsEnvs Field = "ps.envs"
	// PsHandleNames represents the process handles
	PsHandleNames Field = "ps.handles"
	// PsHandleTypes represents the process handle types
	PsHandleTypes Field = "ps.handle.types"
	// PsDTB represents the process directory table base address
	PsDTB Field = "ps.dtb"
	// PsModuleNames represents the process module file names
	PsModuleNames Field = "ps.modules"
	// PsParentPid represents the parent process identifier field
	PsParentPid Field = "ps.parent.pid"
	// PsParentName represents the parent process name field
	PsParentName Field = "ps.parent.name"
	// PsParentComm represents the parent process command line field. Deprecated
	PsParentComm Field = "ps.parent.comm"
	// PsParentCmdline represents the parent process command line field
	PsParentCmdline Field = "ps.parent.cmdline"
	// PsParentExe represents the parent process image path field
	PsParentExe Field = "ps.parent.exe"
	// PsParentArgs represents the parent process command line arguments field
	PsParentArgs Field = "ps.parent.args"
	// PsParentCwd represents the parent process current working directory field
	PsParentCwd Field = "ps.parent.cwd"
	// PsParentSID represents the parent process security identifier field
	PsParentSID Field = "ps.parent.sid"
	// PsParentUsername represents the parent process username field
	PsParentUsername Field = "ps.parent.username"
	// PsParentDomain represents the parent process domain field
	PsParentDomain Field = "ps.parent.domain"
	// PsParentSessionID represents the session id field bound to the parent process
	PsParentSessionID Field = "ps.parent.sessionid"
	// PsParentEnvs represents the parent process environment variables field
	PsParentEnvs Field = "ps.parent.envs"
	// PsParentHandles represents the parent process handles field
	PsParentHandles Field = "ps.parent.handles"
	// PsParentHandleTypes represents the parent process handle types field
	PsParentHandleTypes Field = "ps.parent.handle.types"
	// PsParentDTB represents the parent process directory table base address field
	PsParentDTB Field = "ps.parent.dtb"
	// PsAncestor represents the process ancestor field
	PsAncestor Field = "ps.ancestor"
	// PsAccessMask represents the process access rights field
	PsAccessMask Field = "ps.access.mask"
	// PsAccessMaskNames represents the process access rights list field
	PsAccessMaskNames Field = "ps.access.mask.names"
	// PsAccessStatus represents the process access status field
	PsAccessStatus Field = "ps.access.status"
	// PsIsWOW64Field represents the field that indicates if the 32-bit process is created in 64-bit Windows system
	PsIsWOW64Field Field = "ps.is_wow64"
	// PsIsPackagedField represents the field that indicates if a process is packaged with the MSIX technology
	PsIsPackagedField Field = "ps.is_packaged"
	// PsIsProtectedField represents the field that indicates if the process is to be run as a protected process
	PsIsProtectedField Field = "ps.is_protected"
	// PsParentIsWOW64Field represents the field that indicates if the 32-bit process is created in 64-bit Windows system
	PsParentIsWOW64Field Field = "ps.parent.is_wow64"
	// PsParentIsPackagedField represents the field that indicates if a process is packaged with the MSIX technology
	PsParentIsPackagedField Field = "ps.parent.is_packaged"
	// PsParentIsProtectedField represents the field that indicates if the process is to be run as a protected process
	PsParentIsProtectedField Field = "ps.parent.is_protected"
	// PsUUID represents the unique process identifier
	PsUUID Field = "ps.uuid"
	// PsParentUUID represents the unique parent process identifier
	PsParentUUID Field = "ps.parent.uuid"
	// PsTokenIntegrityLevel represents the field that indicates the current process integrity level
	PsTokenIntegrityLevel = "ps.token.integrity_level"
	// PsTokenIsElevated  represents the field that indicates if the current process token is elevated
	PsTokenIsElevated = "ps.token.is_elevated"
	// PsTokenElevationType represents the field that indicates if the current process token elevation type
	PsTokenElevationType = "ps.token.elevation_type"
	// PsParentTokenIntegrityLevel represents the field that indicates the parent process integrity level
	PsParentTokenIntegrityLevel = "ps.parent.token.integrity_level"
	// PsParentTokenIsElevated  represents the field that indicates if the parent process token is elevated
	PsParentTokenIsElevated = "ps.parent.token.is_elevated"
	// PsTokenElevationType represents the field that indicates if the parent process token elevation type
	PsParentTokenElevationType = "ps.parent.token.elevation_type"
	// PsSignatureExists is the field which indicates if the binary is signed, either by embedded or catalog signature
	PsSignatureExists Field = "ps.signature.exists"
	// PsSignatureTrusted is the field which indicates if the binary signature is trusted
	PsSignatureTrusted Field = "ps.signature.trusted"
	// PsSignatureIssuer is the field which indicates the certificate issuer
	PsSignatureIssuer Field = "ps.signature.issuer"
	// PsSignatureSubject is the field which indicates the certificate subject
	PsSignatureSubject Field = "ps.signature.subject"
	// PsSignatureSerial is the field which indicates the certificate serial
	PsSignatureSerial Field = "ps.signature.serial"
	// PsSignatureAfter is the field which indicates the timestamp after certificate is no longer valid
	PsSignatureAfter Field = "ps.signature.after"
	// PsSignatureBefore is the field which indicates the timestamp of the certificate enrollment date
	PsSignatureBefore Field = "ps.signature.before"

	// PsPeNumSections represents the number of sections
	PsPeNumSections Field = "ps.pe.nsections"
	// PsPeNumSymbols represents the number of exported symbols
	PsPeNumSymbols Field = "ps.pe.nsymbols"
	// PsPeSymbols represents imported symbols
	PsPeSymbols Field = "ps.pe.symbols"
	// PeImports represents imported libraries (e.g. kernel32.dll)
	PsPeImports Field = "ps.pe.imports"
	// PeTimestamp is the PE build timestamp
	PsPeTimestamp Field = "ps.pe.timestamp"
	// PeBaseAddress represents the base address when the binary is loaded
	PsPeBaseAddress Field = "ps.pe.address.base"
	// PeEntrypoint is the address of the entrypoint function
	PsPeEntrypoint Field = "ps.pe.address.entrypoint"
	// PeResources represents PE resources
	PsPeResources Field = "ps.pe.resources"
	// PeCompany represents the company name resource
	PsPeCompany Field = "ps.pe.company"
	// PeDescription represents the internal description of the file
	PsPeDescription Field = "ps.pe.description"
	// PeFileVersion represents the internal file version
	PsPeFileVersion Field = "ps.pe.file.version"
	// PeFileName represents the original file name provided at compile-time.
	PsPeFileName Field = "ps.pe.file.name"
	// PeCopyright represents the copyright notice emitted at compile-time
	PsPeCopyright Field = "ps.pe.copyright"
	// PeProduct represents the product name provided at compile-time
	PsPeProduct Field = "ps.pe.product"
	// PeProductVersion represents the internal product version provided at compile-time
	PsPeProductVersion Field = "ps.pe.product.version"
	// PeAnomalies represents the field that contains PE anomalies detected during parsing
	PsPeAnomalies Field = "ps.pe.anomalies"
	// PsPeImphash is the field that yields the PE import hash
	PsPeImphash Field = "ps.pe.imphash"
	// PsPeIsDotnet is the field which indicates if the binary contains the .NET assembly
	PsPeIsDotnet Field = "ps.pe.is_dotnet"
	// PsPeIsModified is the field that indicates whether disk and in-memory PE headers differ
	PsPeIsModified Field = "ps.pe.is_modified"

	// ThreadBasePrio is the base thread priority
	ThreadBasePrio Field = "thread.prio"
	// ThreadIOPrio is the thread I/O priority
	ThreadIOPrio Field = "thread.io.prio"
	// ThreadPagePrio is the thread page priority
	ThreadPagePrio Field = "thread.page.prio"
	// ThreadKstackBase is the thread kernel stack start address
	ThreadKstackBase Field = "thread.kstack.base"
	// ThreadKstackLimit is the thread kernel stack end address
	ThreadKstackLimit Field = "thread.kstack.limit"
	// ThreadUstackBase is the thread user stack start address
	ThreadUstackBase Field = "thread.ustack.base"
	// ThreadUstackLimit is the thead user stack end address
	ThreadUstackLimit Field = "thread.ustack.limit"
	// ThreadEntrypoint is the thread entrypoint address
	ThreadEntrypoint Field = "thread.entrypoint"
	// ThreadStartAddress is the thread start address
	ThreadStartAddress Field = "thread.start_address"
	// ThreadPID is the process identifier where the thread is created
	ThreadPID Field = "thread.pid"
	// ThreadTEB is the thread environment block base address
	ThreadTEB Field = "thread.teb_address"
	// ThreadAccessMask represents the thread access rights field
	ThreadAccessMask Field = "thread.access.mask"
	// ThreadAccessMaskNames represents the thread access rights list field
	ThreadAccessMaskNames Field = "thread.access.mask.names"
	// ThreadAccessStatus represents the thread access status field
	ThreadAccessStatus Field = "thread.access.status"
	// ThreadCallstackSummary represents the thread callstack summary field
	ThreadCallstackSummary Field = "thread.callstack.summary"
	// ThreadCallstackKernelSummary represents the kernel thread callstack summary field
	ThreadCallstackKernelSummary Field = "thread.callstack.kernel_summary"
	// ThreadCallstackDetail represents the thread callstack detail field
	ThreadCallstackDetail Field = "thread.callstack.detail"
	// ThreadCallstackModules represents the callstack modules field
	ThreadCallstackModules Field = "thread.callstack.modules"
	// ThreadCallstackSymbols represents the callstack symbols field
	ThreadCallstackSymbols Field = "thread.callstack.symbols"
	// ThreadCallstackProtections represents the callstack region protections field
	ThreadCallstackProtections Field = "thread.callstack.protections"
	// ThreadCallstackAllocationSizes represents the private region page sizes field
	ThreadCallstackAllocationSizes Field = "thread.callstack.allocation_sizes"
	// ThreadCallstackCallsiteLeadingAssembly represents the callsite prelude opcodes field
	ThreadCallstackCallsiteLeadingAssembly Field = "thread.callstack.callsite_leading_assembly"
	// ThreadCallstackCallsiteTrailingAssembly represents the callsite postlude opcodes field
	ThreadCallstackCallsiteTrailingAssembly Field = "thread.callstack.callsite_trailing_assembly"
	// ThreadCallstackIsUnbacked represents the field that indicates if there is an unbacked stack frame
	ThreadCallstackIsUnbacked Field = "thread.callstack.is_unbacked"
	// ThreadStartAddressSymbol represents the symbol corresponding to the thread start address
	ThreadStartAddressSymbol Field = "thread.start_address.symbol"
	// ThreadStartAddressModule represents the module corresponding to the thread start address
	ThreadStartAddressModule Field = "thread.start_address.module"
	// ThreadCallstackAddresses represents the all callstack return addresses
	ThreadCallstackAddresses Field = "thread.callstack.addresses"
	// ThreadCallstackFinalUserModuleName represents the final user space stack frame module name
	ThreadCallstackFinalUserModuleName Field = "thread.callstack.final_user_module.name"
	// ThreadCallstackFinalUserModulePath represents the final user space stack frame module path
	ThreadCallstackFinalUserModulePath Field = "thread.callstack.final_user_module.path"
	// ThreadCallstackFinalUserSymbolName represents the final user space stack frame symbol name
	ThreadCallstackFinalUserSymbolName Field = "thread.callstack.final_user_symbol.name"
	// ThreadCallstackFinalKernelModuleName represents the final kernel space stack frame module name
	ThreadCallstackFinalKernelModuleName Field = "thread.callstack.final_kernel_module.name"
	// ThreadCallstackFinalKernelModulePath represents the final kernel space stack frame module name
	ThreadCallstackFinalKernelModulePath Field = "thread.callstack.final_kernel_module.path"
	// ThreadCallstackFinalKernelSymbolName represents the final kernel space stack frame symbol name
	ThreadCallstackFinalKernelSymbolName Field = "thread.callstack.final_kernel_symbol.name"
	// ThreadCallstackFinalUserModuleSignatureExists represents the signature status of the final user space stack frame module
	ThreadCallstackFinalUserModuleSignatureExists Field = "thread.callstack.final_user_module.signature.exists"
	// ThreadCallstackFinalUserModuleSignatureTrusted represents the trust status of the final user space stack frame module signature
	ThreadCallstackFinalUserModuleSignatureTrusted Field = "thread.callstack.final_user_module.signature.trusted"
	// ThreadCallstackFinalUserModuleSignatureIssuer represents the final user space stack frame module certificate issuer
	ThreadCallstackFinalUserModuleSignatureIssuer Field = "thread.callstack.final_user_module.signature.issuer"
	// ThreadCallstackFinalUserModuleSignatureSubject represents the final user space stack frame module certificate subject
	ThreadCallstackFinalUserModuleSignatureSubject Field = "thread.callstack.final_user_module.signature.subject"

	// PeNumSections represents the number of sections
	PeNumSections Field = "pe.nsections"
	// PeNumSymbols represents the number of exported symbols
	PeNumSymbols Field = "pe.nsymbols"
	// PeSymbols represents imported symbols
	PeSymbols Field = "pe.symbols"
	// PeImports represents imported libraries (e.g. kernel32.dll)
	PeImports Field = "pe.imports"
	// PeTimestamp is the PE build timestamp
	PeTimestamp Field = "pe.timestamp"
	// PeBaseAddress represents the base address when the binary is loaded
	PeBaseAddress Field = "pe.address.base"
	// PeEntrypoint is the address of the entrypoint function
	PeEntrypoint Field = "pe.address.entrypoint"
	// PeResources represents PE resources
	PeResources Field = "pe.resources"
	// PeCompany represents the company name resource
	PeCompany Field = "pe.company"
	// PeDescription represents the internal description of the file
	PeDescription Field = "pe.description"
	// PeFileVersion represents the internal file version
	PeFileVersion Field = "pe.file.version"
	// PeFileName represents the original file name provided at compile-time.
	PeFileName Field = "pe.file.name"
	// PeCopyright represents the copyright notice emitted at compile-time
	PeCopyright Field = "pe.copyright"
	// PeProduct represents the product name provided at compile-time
	PeProduct Field = "pe.product"
	// PeProductVersion represents the internal product version provided at compile-time
	PeProductVersion Field = "pe.product.version"
	// PeIsDLL indicates if the file is a DLL
	PeIsDLL Field = "pe.is_dll"
	// PeIsDriver indicates if the file is a driver
	PeIsDriver Field = "pe.is_driver"
	// PeIsExecutable indicates if the file is an executable
	PeIsExecutable Field = "pe.is_exec"
	// PeAnomalies represents the field that contains PE anomalies detected during parsing
	PeAnomalies Field = "pe.anomalies"
	// PeImphash is the field that yields the PE import hash
	PeImphash Field = "pe.imphash"
	// PeIsDotnet is the field which indicates if the binary contains the .NET assembly
	PeIsDotnet Field = "pe.is_dotnet"
	// PeIsSigned is the field which indicates if the binary is signed, either by embedded or catalog signature
	PeIsSigned Field = "pe.is_signed"
	// PeIsTrusted is the field which indicates if the binary signature is trusted
	PeIsTrusted Field = "pe.is_trusted"
	// PeCertIssuer is the field which indicates the certificate issuer
	PeCertIssuer Field = "pe.cert.issuer"
	// PeCertSubject is the field which indicates the certificate subject
	PeCertSubject Field = "pe.cert.subject"
	// PeCertSerial is the field which indicates the certificate serial
	PeCertSerial Field = "pe.cert.serial"
	// PeCertAfter is the field which indicates the timestamp after certificate is no longer valid
	PeCertAfter Field = "pe.cert.after"
	// PeCertBefore is the field which indicates the timestamp of the certificate enrollment date
	PeCertBefore Field = "pe.cert.before"
	// PeIsModified is the field that indicates whether disk and in-memory PE headers differ
	PeIsModified Field = "pe.is_modified"

	// EvtSeq is the event sequence number
	EvtSeq Field = "evt.seq"
	// EvtPID is the process identifier that generated the event
	EvtPID Field = "evt.pid"
	// EvtTID is the thread identifier that generated the event
	EvtTID Field = "evt.tid"
	// EvtCPU is the CPU core where the event was generated
	EvtCPU Field = "evt.cpu"
	// EvtDesc represents the event description
	EvtDesc Field = "evt.desc"
	// EvtHost represents the host where the event was produced
	EvtHost Field = "evt.host"
	// EvtTime is the event time
	EvtTime Field = "evt.time"
	// EvtTimeHour is the hour part of the event time
	EvtTimeHour Field = "evt.time.h"
	// EvtTimeMin is the minute part of the event time
	EvtTimeMin Field = "evt.time.m"
	// EvtTimeSec is the second part of the event time
	EvtTimeSec Field = "evt.time.s"
	// EvtTimeNs is the nanosecond part of the event time
	EvtTimeNs Field = "evt.time.ns"
	// EvtDate is the event date
	EvtDate Field = "evt.date"
	// EvtDateDay is the day of event date
	EvtDateDay Field = "evt.date.d"
	// EvtDateMonth is the month of event date
	EvtDateMonth Field = "evt.date.m"
	// EvtDateYear is the year of event date
	EvtDateYear Field = "evt.date.y"
	// EvtDateTz is the time zone of event timestamp
	EvtDateTz Field = "evt.date.tz"
	// EvtDateWeek is the event week number
	EvtDateWeek Field = "evt.date.week"
	// EvtDateWeekday is the event week day
	EvtDateWeekday Field = "evt.date.weekday"
	// EvtName is the event name
	EvtName Field = "evt.name"
	// EvtCategory is the event category
	EvtCategory Field = "evt.category"
	// EvtNparams is the number of event parameters
	EvtNparams Field = "evt.nparams"
	// EvtArg represents the field sequence for generic argument access
	EvtArg Field = "evt.arg"
	// EvtIsDirectSyscall represents the field that designates if this event is
	// performing a direct syscall.
	EvtIsDirectSyscall Field = "evt.is_direct_syscall"
	// EvtIsIndirectSyscall represents the field that designates if this event is
	// performing an indirect syscall.
	EvtIsIndirectSyscall Field = "evt.is_indirect_syscall"

	// KevtSeq is the event sequence number
	KevtSeq Field = "kevt.seq"
	// KevtPID is the process identifier that generated the event
	KevtPID Field = "kevt.pid"
	// KevtTID is the thread identifier that generated the event
	KevtTID Field = "kevt.tid"
	// KevtCPU is the CPU core where the event was generated
	KevtCPU Field = "kevt.cpu"
	// KevtDesc represents the event description
	KevtDesc Field = "kevt.desc"
	// KevtHost represents the host where the event was produced
	KevtHost Field = "kevt.host"
	// KevtTime is the event time
	KevtTime Field = "kevt.time"
	// KevtTimeHour is the hour part of the event time
	KevtTimeHour Field = "kevt.time.h"
	// KevtTimeMin is the minute part of the event time
	KevtTimeMin Field = "kevt.time.m"
	// KevtTimeSec is the second part of the event time
	KevtTimeSec Field = "kevt.time.s"
	// KevtTimeNs is the nanosecond part of the event time
	KevtTimeNs Field = "kevt.time.ns"
	// KevtDate is the event date
	KevtDate Field = "kevt.date"
	// KevtDateDay is the day of event date
	KevtDateDay Field = "kevt.date.d"
	// KevtDateMonth is the month of event date
	KevtDateMonth Field = "kevt.date.m"
	// KevtDateYear is the year of event date
	KevtDateYear Field = "kevt.date.y"
	// KevtDateTz is the time zone of event timestamp
	KevtDateTz Field = "kevt.date.tz"
	// KevtDateWeek is the event week number
	KevtDateWeek Field = "kevt.date.week"
	// KevtDateWeekday is the event week day
	KevtDateWeekday Field = "kevt.date.weekday"
	// KevtName is the event name
	KevtName Field = "kevt.name"
	// KevtCategory is the event category
	KevtCategory Field = "kevt.category"
	// KevtNparams is the number of event parameters
	KevtNparams Field = "kevt.nparams"
	// KevtArg represents the field sequence for generic argument access
	KevtArg Field = "kevt.arg"

	// HandleID represents the handle identifier within the process address space
	HandleID Field = "handle.id"
	// HandleObject represents the handle object address
	HandleObject Field = "handle.object"
	// HandleName represents the handle name
	HandleName Field = "handle.name"
	// HandleType represents the handle type (e.g. file)
	HandleType Field = "handle.type"

	// NetDIP represents network destination IP address
	NetDIP Field = "net.dip"
	// NetSIP represents the source IP address
	NetSIP Field = "net.sip"
	// NetDport represents the destination port
	NetDport Field = "net.dport"
	// NetSport represents the source port
	NetSport Field = "net.sport"
	// NetDportName represents the destination port IANA name
	NetDportName Field = "net.dport.name"
	// NetSportName represents the source port IANA name
	NetSportName Field = "net.sport.name"
	// NetL4Proto represents the Layer4 protocol name (e.g. TCP)
	NetL4Proto Field = "net.l4.proto"
	// NetPacketSize represents the packet size
	NetPacketSize Field = "net.size"
	// NetSIPNames represents the source IP names
	NetSIPNames Field = "net.sip.names"
	// NetDIPNames represents the destination IP names
	NetDIPNames Field = "net.dip.names"

	// FileObject represents the address of the file object
	FileObject Field = "file.object"
	// FileName represents the file base name (e.g. cmd.exe)
	FileName Field = "file.name"
	// FilePath represents the file full path (e.g. C:\Windows\System32\cmd.exe)
	FilePath Field = "file.path"
	// FilePathStem represents the full file path without extension (e.g. C:\Windows\System32\cmd)
	FilePathStem Field = "file.path.stem"
	// FileExtension represents the file extension (e.g. .exe or .dll)
	FileExtension Field = "file.extension"
	// FileOperation represents the file operation (e.g. create)
	FileOperation Field = "file.operation"
	// FileShareMask represents the file share mask
	FileShareMask Field = "file.share.mask"
	// FileShareMode represents the file share mode field
	FileShareMode Field = "file.share_mode"
	// FileIOSize represents the number of read/written bytes
	FileIOSize Field = "file.io.size"
	// FileOffset represents the read/write offset
	FileOffset Field = "file.offset"
	// FileType represents the file type
	FileType Field = "file.type"
	// FileAttributes represents a slice of file attributes
	FileAttributes Field = "file.attributes"
	// FileStatus represents the status message of the file operation
	FileStatus Field = "file.status"
	// FileViewBase represents the base address of the mapped view
	FileViewBase Field = "file.view.base"
	// FileViewSize represents the size of the mapped view
	FileViewSize Field = "file.view.size"
	// FileViewType represents the type of the mapped view section
	FileViewType Field = "file.view.type"
	// FileViewProtection represents the protection attributes of the section view
	FileViewProtection Field = "file.view.protection"
	// FileIsDLL indicates if the created file is a DLL
	FileIsDLL Field = "file.is_dll"
	// FileIsDriver indicates if the created file is a driver
	FileIsDriver Field = "file.is_driver"
	// FileIsExecutable indicates if the created file is an executable
	FileIsExecutable Field = "file.is_exec"
	// FilePID represents the field that denotes the process id performing file operations
	FilePID Field = "file.pid"
	// FileKey represents the field that uniquely identifies the file object.
	FileKey Field = "file.key"
	// FileInfoClass represents the field that identifies the file information class
	FileInfoClass Field = "file.info_class"
	// FileInfoAllocationSize represents the field that contains the file allocation size
	FileInfoAllocationSize Field = "file.info.allocation_size"
	// FileInfoEOFSize represents the field that contains the EOF size
	FileInfoEOFSize Field = "file.info.eof_size"
	// FileInfoIsDispositionDeleteFile represents the field that indicates if the file is deleted when its handle is closed
	FileInfoIsDispositionDeleteFile Field = "file.info.is_disposition_delete_file"

	// RegistryPath represents the full registry path
	RegistryPath Field = "registry.path"
	// RegistryKeyName represents the registry key name
	RegistryKeyName Field = "registry.key.name"
	// RegistryKCB represents the registry KCB address
	RegistryKCB Field = "registry.kcb"
	// RegistryValue represents the registry value name field
	RegistryValue Field = "registry.value"
	// RegistryValueType represents the registry value type field
	RegistryValueType Field = "registry.value.type"
	// RegistryData represents the captured registry data field
	RegistryData Field = "registry.data"
	// RegistryStatus represent the registry operation status
	RegistryStatus Field = "registry.status"

	// ImageBase is the module base address
	ImageBase Field = "image.base.address"
	// ImageSize is the module size
	ImageSize Field = "image.size"
	// ImageChecksum represents the module checksum hash
	ImageChecksum Field = "image.checksum"
	// ImageDefaultAddress represents the module address
	ImageDefaultAddress Field = "image.default.address"
	// ImagePath is the module full path
	ImagePath Field = "image.path"
	// ImageName is the module name
	ImageName Field = "image.name"
	// ImagePID is the pid of the process where the image was loaded
	ImagePID Field = "image.pid"
	// ImageSignatureType represents the image signature type
	ImageSignatureType Field = "image.signature.type"
	// ImageSignatureLevel represents the image signature level
	ImageSignatureLevel Field = "image.signature.level"
	// ImageCertSubject is the field that indicates the subject of the certificate is the entity its public key is associated with.
	ImageCertSubject = "image.cert.subject"
	// ImageCertIssuer is the field that represents the certificate authority (CA).
	ImageCertIssuer = "image.cert.issuer"
	// ImageCertSerial is the field that represents the serial number MUST be a positive integer assigned
	// by the CA to each certificate.
	ImageCertSerial = "image.cert.serial"
	// ImageCertBefore is the field that specifies the certificate won't be valid before this timestamp.
	ImageCertBefore = "image.cert.before"
	// ImageCertAfter is the field that specifies the certificate won't be valid after this timestamp.
	ImageCertAfter = "image.cert.after"
	// ImageIsDLL indicates if the loaded image is a DLL
	ImageIsDLL Field = "image.is_dll"
	// ImageIsDriver indicates if the loaded image is a driver
	ImageIsDriver Field = "image.is_driver"
	// ImageIsExecutable indicates if the loaded image is an executable
	ImageIsExecutable Field = "image.is_exec"
	// ImageIsDotnet indicates if the loaded image is a .NET assembly
	ImageIsDotnet Field = "image.is_dotnet"

	// DllBase is the DLL base address
	DllBase Field = "dll.base"
	// DllSize is the DLL virtual mapped space size
	DllSize Field = "dll.size"
	// DllPath is the DLL full path
	DllPath Field = "dll.path"
	// DllPath is the DLL path stem field
	DllPathStem Field = "dll.path.stem"
	// DllName is the DLL name
	DllName Field = "dll.name"
	// DllPID is the pid of the process where the DLL was loaded
	DllPID Field = "dll.pid"
	// DllSignatureType represents the DLL signature type
	DllSignatureType Field = "dll.signature.type"
	// DllSignatureLevel represents the DLL signature level
	DllSignatureLevel Field = "dll.signature.level"
	// DllSignatureExists is the field that determines if the DLL signature exists
	DllSignatureExists Field = "dll.signature.exists"
	// DllSignatureTrusted is the filed that determines if the DLL signature is trusted
	DllSignatureTrusted Field = "dll.signature.trusted"
	// DllSignatureSubject is the field that indicates the subject of the certificate is the entity its public key is associated with.
	DllSignatureSubject = "dll.signature.subject"
	// DllSignatureIssuer is the field that represents the certificate authority (CA).
	DllSignatureIssuer = "dll.signature.issuer"
	// DllSignatureSerial is the field that represents the serial number MUST be a positive integer assigned
	// by the CA to each certificate.
	DllSignatureSerial = "dll.signature.serial"
	// DllSignatureBefore is the field that specifies the certificate won't be valid before this timestamp.
	DllSignatureBefore = "dll.signature.before"
	// DllSignatureAfter is the field that specifies the certificate won't be valid after this timestamp.
	DllSignatureAfter = "dll.signature.after"
	// DllIsDotnet indicates if the DLL is a .NET assembly.
	DllIsDotnet Field = "dll.pe.is_dotnet"

	// ModuleBase is the module base address
	ModuleBase Field = "module.base"
	// ModuleSize is the module size
	ModuleSize Field = "module.size"
	// ModuleChecksum represents the module checksum hash
	ModuleChecksum Field = "module.checksum"
	// ModuleDefaultAddress represents the module address
	ModuleDefaultAddress Field = "module.default_address"
	// ModulePath is the module full path
	ModulePath Field = "module.path"
	// ModulePathStem is the module path stem field
	ModulePathStem Field = "module.path.stem"
	// ModuleName is the module name
	ModuleName Field = "module.name"
	// ModulePID is the pid of the process where the module was loaded
	ModulePID Field = "module.pid"
	// ModuleSignatureType represents the module signature type
	ModuleSignatureType Field = "module.signature.type"
	// ModuleSignatureLevel represents the module signature level
	ModuleSignatureLevel Field = "module.signature.level"
	// ModuleSignatureExists is the field that determines if the module signature exists
	ModuleSignatureExists Field = "module.signature.exists"
	// ModuleSignatureTrusted is the filed that determines if the module signature is trusted
	ModuleSignatureTrusted Field = "module.signature.trusted"
	// ModuleSignatureSubject is the field that indicates the subject of the certificate is the entity its public key is associated with.
	ModuleSignatureSubject = "module.signature.subject"
	// ModuleSignatureIssuer is the field that represents the certificate authority (CA).
	ModuleSignatureIssuer = "module.signature.issuer"
	// ModuleSignatureSerial is the field that represents the serial number MUST be a positive integer assigned
	// by the CA to each certificate.
	ModuleSignatureSerial = "module.signature.serial"
	// ModuleSignatureBefore is the field that specifies the certificate won't be valid before this timestamp.
	ModuleSignatureBefore = "module.signature.before"
	// ModuleSignatureAfter is the field that specifies the certificate won't be valid after this timestamp.
	ModuleSignatureAfter = "module.signature.after"
	// ModuleIsDLL indicates if the loaded module is a DLL
	ModuleIsDLL Field = "module.is_dll"
	// ModuleIsDriver indicates if the loaded module is a driver
	ModuleIsDriver Field = "module.is_driver"
	// ModuleIsExecutable indicates if the loaded module is an executable
	ModuleIsExecutable Field = "module.is_exec"
	// ModuleIsDotnet indicates if the loaded module is a .NET assembly
	ModuleIsDotnet Field = "module.pe.is_dotnet"

	// MemBaseAddress identifies the field that denotes the allocation base address
	MemBaseAddress Field = "mem.address"
	// MemRegionSize Field identifies the field that represents the allocated region size
	MemRegionSize Field = "mem.size"
	// MemAllocType identifies the field that represents region allocation type
	MemAllocType Field = "mem.alloc"
	// MemPageType identifies the parameter that represents the allocated region type
	MemPageType Field = "mem.type"
	// MemProtection identifies the field that represents the memory protection for the range of pages
	MemProtection Field = "mem.protection"
	// MemProtectionMask identifies the field that represents the memory protection in mask notation
	MemProtectionMask Field = "mem.protection.mask"

	// DNSName identifies the field that represents the DNS name
	DNSName Field = "dns.name"
	// DNSRR identifies the field that represents the DNS record type
	DNSRR Field = "dns.rr"
	// DNSOptions identifies the field that represents the DNS options
	DNSOptions Field = "dns.options"
	// DNSAnswers identifies the field that represents the DNS answers
	DNSAnswers Field = "dns.answers"
	// DNSRcode identifies the field that represents the DNS response code
	DNSRcode Field = "dns.rcode"

	// ThreadpoolPoolID identifies the field that represents the thread pool identifier
	ThreadpoolPoolID = "threadpool.id"
	// ThreadpoolTaskID identifies the field that represents the thread pool task identifier
	ThreadpoolTaskID = "threadpool.task.id"
	// ThreadpoolCallbackAddress identifies the field that represents the address of the callback function
	ThreadpoolCallbackAddress = "threadpool.callback.address"
	// ThreadpoolCallbackSymbol identifies the field that represents the callback symbol
	ThreadpoolCallbackSymbol = "threadpool.callback.symbol"
	// ThreadpoolCallbackModule identifies the field that represents the module containing the callback symbol
	ThreadpoolCallbackModule = "threadpool.callback.module"
	// ThreadpoolCallbackContext identifies the field that represents the address of the callback context
	ThreadpoolCallbackContext = "threadpool.callback.context"
	// ThreadpoolCallbackContextRip identifies the field that represents the value of instruction pointer contained in the callback context
	ThreadpoolCallbackContextRip = "threadpool.callback.context.rip"
	// ThreadpoolCallbackContextRipSymbol identifies the field that represents the symbol name associated with the instruction pointer in callback context
	ThreadpoolCallbackContextRipSymbol = "threadpool.callback.context.rip.symbol"
	// ThreadpoolCallbackContextRipModule identifies the field that represents the module name associated with the instruction pointer in callback context
	ThreadpoolCallbackContextRipModule = "threadpool.callback.context.rip.module"
	// ThreadpoolSubprocessTag identifies the field that represents the service identifier associated with the thread pool
	ThreadpoolSubprocessTag = "threadpool.subprocess_tag"
	// ThreadpoolTimerDuetime identifies the field that represents the timer due time
	ThreadpoolTimerDuetime = "threadpool.timer.duetime"
	// ThreadpoolTimerSubqueue identifies the field that represents the memory address of the timer subqueue
	ThreadpoolTimerSubqueue = "threadpool.timer.subqueue"
	// ThreadpoolTimer identifies the field that represents the memory address of the timer object
	ThreadpoolTimer = "threadpool.timer.address"
	// ThreadpoolTimerPeriod identifies the field that represents the period of the timer
	ThreadpoolTimerPeriod = "threadpool.timer.period"
	// ThreadpoolTimerWindow identifies the field that represents the timer tolerate period
	ThreadpoolTimerWindow = "threadpool.timer.window"
	// ThreadpoolTimerAbsolute identifies the field that indicates if the timer is absolute or relative
	ThreadpoolTimerAbsolute = "threadpool.timer.is_absolute"
)

// String casts the field type to string.
func (f Field) String() string { return string(f) }

// Type returns the data type that this field contains.
func (f Field) Type() params.Type { return fields[f].Type }

func (f Field) IsPsField() bool       { return strings.HasPrefix(string(f), "ps.") }
func (f Field) IsKevtField() bool     { return strings.HasPrefix(string(f), "kevt.") }
func (f Field) IsEvtField() bool      { return strings.HasPrefix(string(f), "evt.") }
func (f Field) IsThreadField() bool   { return strings.HasPrefix(string(f), "thread.") }
func (f Field) IsImageField() bool    { return strings.HasPrefix(string(f), "image.") }
func (f Field) IsFileField() bool     { return strings.HasPrefix(string(f), "file.") }
func (f Field) IsRegistryField() bool { return strings.HasPrefix(string(f), "registry.") }
func (f Field) IsNetworkField() bool  { return strings.HasPrefix(string(f), "net.") }
func (f Field) IsHandleField() bool   { return strings.HasPrefix(string(f), "handle.") }
func (f Field) IsPeField() bool {
	return strings.HasPrefix(string(f), "pe.") || strings.HasPrefix(string(f), "ps.pe.") || strings.HasPrefix(string(f), "ps.signature.")
}
func (f Field) IsModuleField() bool {
	return strings.HasPrefix(string(f), "module.") || strings.HasPrefix(string(f), "dll.")
}
func (f Field) IsMemField() bool        { return strings.HasPrefix(string(f), "mem.") }
func (f Field) IsDNSField() bool        { return strings.HasPrefix(string(f), "dns.") }
func (f Field) IsThreadpoolField() bool { return strings.HasPrefix(string(f), "threadpool.") }

func (f Field) IsPeSection() bool { return f == PeNumSections || f == PsPeNumSections }
func (f Field) IsPeSymbol() bool {
	return f == PeSymbols || f == PeNumSymbols || f == PeImports || f == PsPeSymbols || f == PsPeNumSymbols || f == PsPeImports
}
func (f Field) IsPeVersionResource() bool {
	return f == PeCompany || f == PeCopyright || f == PeDescription || f == PeFileName || f == PeFileVersion || f == PeProduct || f == PeProductVersion ||
		f == PsPeCompany || f == PsPeCopyright || f == PsPeDescription || f == PsPeFileName || f == PsPeFileVersion || f == PsPeProduct || f == PsPeProductVersion
}
func (f Field) IsPeVersionResources() bool { return f == PeResources || f == PsPeResources }
func (f Field) IsPeImphash() bool          { return f == PeImphash || f == PsPeImphash }
func (f Field) IsPeDotnet() bool           { return f == PeIsDotnet || f == PsPeIsDotnet }
func (f Field) IsPeAnomalies() bool        { return f == PeAnomalies || f == PsPeAnomalies }
func (f Field) IsPeSignature() bool {
	return f == PeIsTrusted || f == PeIsSigned || f == PeCertIssuer || f == PeCertSerial || f == PeCertSubject || f == PeCertBefore || f == PeCertAfter || strings.HasPrefix(string(f), "ps.signature.")
}
func (f Field) IsPeIsTrusted() bool { return f == PeIsTrusted || f == PsSignatureTrusted }
func (f Field) IsPeIsSigned() bool  { return f == PeIsSigned || f == PsSignatureExists }

func (f Field) IsPeCert() bool {
	return strings.HasPrefix(string(f), "pe.cert.") || f == PsSignatureIssuer || f == PsSignatureSubject || f == PsSignatureSerial || f == PsSignatureAfter || f == PsSignatureBefore
}
func (f Field) IsImageCert() bool { return strings.HasPrefix(string(f), "image.cert.") }
func (f Field) IsModuleCert() bool {
	return f == ModuleSignatureSubject || f == ModuleSignatureIssuer || f == ModuleSignatureSerial || f == ModuleSignatureAfter || f == ModuleSignatureBefore ||
		f == DllSignatureSubject || f == DllSignatureIssuer || f == DllSignatureSerial || f == DllSignatureAfter || f == DllSignatureBefore
}
func (f Field) IsModuleSignature() bool {
	return strings.HasPrefix(string(f), "module.signature.") || strings.HasPrefix(string(f), "dll.signature.")
}

func (f Field) IsPeModified() bool { return f == PeIsModified || f == PsPeIsModified }

// Segment represents the type alias for the segment. Segment
// denotes the property anchored to the bound field reference.
// Let's look through an example. $module.name is the literal
// composed of bound field ($module) and the segment (name).
// Segments are most commonly used in the context of bound
// variables in foreach function.
type Segment string

const (
	PathSegment     Segment = "path"
	NameSegment     Segment = "name"
	TypeSegment     Segment = "type"
	SizeSegment     Segment = "size"
	ChecksumSegment Segment = "checksum"
	AddressSegment  Segment = "address"
	OffsetSegment   Segment = "offset"
	EntropySegment  Segment = "entropy"
	MD5Segment      Segment = "md5"

	PIDSegment                 Segment = "pid"
	CmdlineSegment             Segment = "cmdline"
	ExeSegment                 Segment = "exe"
	ArgsSegment                Segment = "args"
	CwdSegment                 Segment = "cwd"
	SIDSegment                 Segment = "sid"
	SessionIDSegment           Segment = "sessionid"
	UsernameSegment            Segment = "username"
	DomainSegment              Segment = "domain"
	TokenIntegrityLevelSegment Segment = "token.integrity_level"
	TokenIsElevatedSegment     Segment = "token.is_elevated"
	TokenElevationTypeSegment  Segment = "token.elevation_type"

	TidSegment              Segment = "tid"
	StartAddressSegment     Segment = "start_address"
	UserStackBaseSegment    Segment = "user_stack_base"
	UserStackLimitSegment   Segment = "user_stack_limit"
	KernelStackBaseSegment  Segment = "kernel_stack_base"
	KernelStackLimitSegment Segment = "kernel_stack_limit"

	SymbolSegment                   Segment = "symbol"
	ModuleSegment                   Segment = "module"
	AllocationSizeSegment           Segment = "allocation_size"
	ProtectionSegment               Segment = "protection"
	IsUnbackedSegment               Segment = "is_unbacked"
	CallsiteLeadingAssemblySegment  Segment = "callsite_leading_assembly"
	CallsiteTrailingAssemblySegment Segment = "callsite_trailing_assembly"

	ModuleSignatureExistsSegment  Segment = "module.signature.exists"
	ModuleSignatureTrustedSegment Segment = "module.signature.trusted"
	ModuleSignatureIssuerSegment  Segment = "module.signature.issuer"
	ModuleSignatureSubjectSegment Segment = "module.signature.subject"
)

var segments = map[Segment]bool{
	NameSegment:                     true,
	PathSegment:                     true,
	TypeSegment:                     true,
	EntropySegment:                  true,
	SizeSegment:                     true,
	MD5Segment:                      true,
	AddressSegment:                  true,
	ChecksumSegment:                 true,
	PIDSegment:                      true,
	CmdlineSegment:                  true,
	ExeSegment:                      true,
	ArgsSegment:                     true,
	CwdSegment:                      true,
	SIDSegment:                      true,
	SessionIDSegment:                true,
	UsernameSegment:                 true,
	DomainSegment:                   true,
	TokenIntegrityLevelSegment:      true,
	TokenIsElevatedSegment:          true,
	TokenElevationTypeSegment:       true,
	TidSegment:                      true,
	StartAddressSegment:             true,
	UserStackBaseSegment:            true,
	UserStackLimitSegment:           true,
	KernelStackBaseSegment:          true,
	KernelStackLimitSegment:         true,
	OffsetSegment:                   true,
	SymbolSegment:                   true,
	ModuleSegment:                   true,
	AllocationSizeSegment:           true,
	ProtectionSegment:               true,
	IsUnbackedSegment:               true,
	CallsiteLeadingAssemblySegment:  true,
	CallsiteTrailingAssemblySegment: true,
	ModuleSignatureExistsSegment:    true,
	ModuleSignatureTrustedSegment:   true,
	ModuleSignatureIssuerSegment:    true,
	ModuleSignatureSubjectSegment:   true,
}

var allowedSegments = map[Field][]Segment{
	PsAncestors:     {NameSegment, PIDSegment, CmdlineSegment, ExeSegment, ArgsSegment, CwdSegment, SIDSegment, SessionIDSegment, UsernameSegment, DomainSegment, TokenIntegrityLevelSegment, TokenIsElevatedSegment, TokenElevationTypeSegment},
	PsThreads:       {TidSegment, StartAddressSegment, UserStackBaseSegment, UserStackLimitSegment, KernelStackBaseSegment, KernelStackLimitSegment},
	PsModules:       {PathSegment, NameSegment, AddressSegment, SizeSegment, ChecksumSegment},
	PsMmaps:         {AddressSegment, TypeSegment, SizeSegment, ProtectionSegment, PathSegment},
	PeSections:      {NameSegment, SizeSegment, EntropySegment, MD5Segment},
	PsPeSections:    {NameSegment, SizeSegment, EntropySegment, MD5Segment},
	ThreadCallstack: {AddressSegment, OffsetSegment, SymbolSegment, ModuleSegment, AllocationSizeSegment, ProtectionSegment, IsUnbackedSegment, CallsiteLeadingAssemblySegment, CallsiteTrailingAssemblySegment, ModuleSignatureExistsSegment, ModuleSignatureTrustedSegment, ModuleSignatureIssuerSegment, ModuleSignatureSubjectSegment},
}

func (s Segment) IsEntropy() bool { return s == EntropySegment }

// IsSegmentAllowed determines if the segment is valid for the pseudo field.
func IsSegmentAllowed(f Field, s Segment) bool {
	segs := allowedSegments[f]
	if len(segs) == 0 {
		return false
	}

	for _, seg := range segs {
		if seg == s {
			return true
		}
	}

	return false
}

// SegmentsHint returns the sequence of available segments for the pseudo field.
func SegmentsHint(f Field) string {
	segs := allowedSegments[f]
	if len(segs) == 0 {
		return ""
	}

	s := make([]string, len(segs))
	for i, seg := range segs {
		s[i] = string(seg)
	}

	return strings.Join(s, ", ")
}

// IsSegment indicates if the given string is recognized as a known segment.
func IsSegment(s string) bool {
	return segments[Segment(s)]
}

// Pseudo fields provide access to the process/event internal state. They
// are typically used in conjunction with the foreach function as its
// first argument.

var (
	PsModules       Field = "ps._modules"
	PsThreads       Field = "ps._threads"
	PsMmaps         Field = "ps._mmaps"
	PsAncestors     Field = "ps._ancestors"
	PsPeSections    Field = "ps.pe._sections"
	ThreadCallstack Field = "thread._callstack"
	PeSections      Field = "pe._sections"
)

func IsPseudoField(f Field) bool {
	return f == PsAncestors || f == PsModules || f == PsThreads || f == PsMmaps || f == ThreadCallstack || f == PeSections || f == PsPeSections
}

func (f Field) IsPeSectionsPseudo() bool { return f == PeSections || f == PsPeSections }

var commonFields = map[Field]FieldInfo{
	EvtSeq:         {EvtSeq, "event sequence number", params.Uint64, []string{"evt.seq > 666"}, nil, nil},
	EvtCPU:         {EvtCPU, "logical processor core where the event was generated", params.Uint8, []string{"evt.cpu = 2"}, nil, nil},
	EvtName:        {EvtName, "symbolical event name", platformAnsiString(), []string{"evt.name = 'CreateThread'"}, nil, nil},
	EvtCategory:    {EvtCategory, "event category", platformAnsiString(), []string{"evt.category = 'registry'"}, nil, nil},
	EvtDesc:        {EvtDesc, "event description", platformAnsiString(), []string{"evt.desc contains 'Creates a new process'"}, nil, nil},
	EvtHost:        {EvtHost, "host name on which the event was produced", platformString(), []string{"evt.host contains 'kitty'"}, nil, nil},
	EvtTime:        {EvtTime, "event timestamp as a time string", params.Time, []string{"evt.time = '17:05:32'"}, nil, nil},
	EvtTimeHour:    {EvtTimeHour, "hour within the day on which the event occurred", params.Time, []string{"evt.time.h = 23"}, nil, nil},
	EvtTimeMin:     {EvtTimeMin, "minute offset within the hour on which the event occurred", params.Time, []string{"evt.time.m = 54"}, nil, nil},
	EvtTimeSec:     {EvtTimeSec, "second offset within the minute  on which the event occurred", params.Time, []string{"evt.time.s = 0"}, nil, nil},
	EvtTimeNs:      {EvtTimeNs, "nanoseconds specified by event timestamp", params.Int64, []string{"evt.time.ns > 1591191629102337000"}, nil, nil},
	EvtDate:        {EvtDate, "event timestamp as a date string", params.Time, []string{"evt.date = '2018-03-03'"}, nil, nil},
	EvtDateDay:     {EvtDateDay, "day of the month on which the event occurred", params.Time, []string{"evt.date.d = 12"}, nil, nil},
	EvtDateMonth:   {EvtDateMonth, "month of the year on which the event occurred", params.Time, []string{"evt.date.m = 11"}, nil, nil},
	EvtDateYear:    {EvtDateYear, "year on which the event occurred", params.Uint32, []string{"evt.date.y = 2020"}, nil, nil},
	EvtDateTz:      {EvtDateTz, "time zone associated with the event timestamp", platformAnsiString(), []string{"evt.date.tz = 'UTC'"}, nil, nil},
	EvtDateWeek:    {EvtDateWeek, "week number within the year on which the event occurred", params.Uint8, []string{"evt.date.week = 2"}, nil, nil},
	EvtDateWeekday: {EvtDateWeekday, "week day on which the event occurred", platformAnsiString(), []string{"evt.date.weekday = 'Monday'"}, nil, nil},
	EvtNparams:     {EvtNparams, "number of parameters", params.Int8, []string{"evt.nparams > 2"}, nil, nil},
	EvtArg: {EvtArg, "event parameter", params.Object, []string{"evt.arg[cmdline] istartswith 'C:\\Windows'"}, nil, &Argument{Optional: false, Pattern: "[a-z0-9_]+", ValidationFunc: func(s string) bool {
		for _, c := range s {
			switch {
			case unicode.IsLower(c):
			case unicode.IsNumber(c):
			case c == '_':
			default:
				return false
			}
		}
		return true
	}}},
	KevtSeq:         {KevtSeq, "event sequence number", params.Uint64, []string{"kevt.seq > 666"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtSeq}}, nil},
	KevtCPU:         {KevtCPU, "logical processor core where the event was generated", params.Uint8, []string{"kevt.cpu = 2"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtCPU}}, nil},
	KevtName:        {KevtName, "symbolical event name", platformAnsiString(), []string{"kevt.name = 'CreateThread'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtName}}, nil},
	KevtCategory:    {KevtCategory, "event category", platformAnsiString(), []string{"kevt.category = 'registry'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtCategory}}, nil},
	KevtDesc:        {KevtDesc, "event description", platformAnsiString(), []string{"kevt.desc contains 'Creates a new process'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDesc}}, nil},
	KevtHost:        {KevtHost, "host name on which the event was produced", platformString(), []string{"kevt.host contains 'kitty'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtHost}}, nil},
	KevtTime:        {KevtTime, "event timestamp as a time string", params.Time, []string{"kevt.time = '17:05:32'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtTime}}, nil},
	KevtTimeHour:    {KevtTimeHour, "hour within the day on which the event occurred", params.Time, []string{"kevt.time.h = 23"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtTimeHour}}, nil},
	KevtTimeMin:     {KevtTimeMin, "minute offset within the hour on which the event occurred", params.Time, []string{"kevt.time.m = 54"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtTimeMin}}, nil},
	KevtTimeSec:     {KevtTimeSec, "second offset within the minute  on which the event occurred", params.Time, []string{"kevt.time.s = 0"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtTimeSec}}, nil},
	KevtTimeNs:      {KevtTimeNs, "nanoseconds specified by event timestamp", params.Int64, []string{"kevt.time.ns > 1591191629102337000"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtTimeNs}}, nil},
	KevtDate:        {KevtDate, "event timestamp as a date string", params.Time, []string{"kevt.date = '2018-03-03'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDate}}, nil},
	KevtDateDay:     {KevtDateDay, "day of the month on which the event occurred", params.Time, []string{"kevt.date.d = 12"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateDay}}, nil},
	KevtDateMonth:   {KevtDateMonth, "month of the year on which the event occurred", params.Time, []string{"kevt.date.m = 11"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateMonth}}, nil},
	KevtDateYear:    {KevtDateYear, "year on which the event occurred", params.Uint32, []string{"kevt.date.y = 2020"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateYear}}, nil},
	KevtDateTz:      {KevtDateTz, "time zone associated with the event timestamp", platformAnsiString(), []string{"kevt.date.tz = 'UTC'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateTz}}, nil},
	KevtDateWeek:    {KevtDateWeek, "week number within the year on which the event occurred", params.Uint8, []string{"kevt.date.week = 2"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateWeek}}, nil},
	KevtDateWeekday: {KevtDateWeekday, "week day on which the event occurred", platformAnsiString(), []string{"kevt.date.weekday = 'Monday'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateWeekday}}, nil},
	KevtNparams:     {KevtNparams, "number of parameters", params.Int8, []string{"kevt.nparams > 2"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtNparams}}, nil},
	KevtArg: {KevtArg, "event parameter", params.Object, []string{"kevt.arg[cmdline] istartswith 'C:\\Windows'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtArg}}, &Argument{Optional: false, Pattern: "[a-z0-9_]+", ValidationFunc: func(s string) bool {
		for _, c := range s {
			switch {
			case unicode.IsLower(c):
			case unicode.IsNumber(c):
			case c == '_':
			default:
				return false
			}
		}
		return true
	}}},
	PsName:          {PsName, "process image name including the file extension", platformString(), []string{"ps.name contains 'firefox'"}, nil, nil},
	PsCmdline:       {PsCmdline, "process command line", platformString(), []string{"ps.cmdline contains 'java'"}, nil, nil},
	PsExe:           {PsExe, "full name of the process' executable", platformString(), []string{"ps.exe = 'C:\\Windows\\system32\\cmd.exe'"}, nil, nil},
	PsArgs:          {PsArgs, "process command line arguments", params.Slice, []string{"ps.args in ('/cdir', '/-C')"}, nil, nil},
	PsCwd:           {PsCwd, "process current working directory", platformString(), []string{"ps.cwd = 'C:\\Users\\Default'"}, nil, nil},
	PsUsername:      {PsUsername, "process username", platformString(), []string{"ps.username contains 'system'"}, nil, nil},
	PsEnvs:          {PsEnvs, "process environment variables", params.Slice, []string{"ps.envs in ('SystemRoot:C:\\WINDOWS')", "ps.envs[windir] = 'C:\\WINDOWS'"}, nil, &Argument{Optional: true, ValidationFunc: func(arg string) bool { return true }}},
	PsParentName:    {PsParentName, "parent process image name including the file extension", platformString(), []string{"ps.parent.name contains 'cmd.exe'"}, nil, nil},
	PsParentCmdline: {PsParentCmdline, "parent process command line", platformString(), []string{"ps.parent.cmdline contains 'java'"}, nil, nil},
	PsParentExe:     {PsParentExe, "full name of the parent process' executable", platformString(), []string{"ps.parent.exe = 'C:\\Windows\\system32\\explorer.exe'"}, nil, nil},
}

func platformFields(platform map[Field]FieldInfo) map[Field]FieldInfo {
	fields := make(map[Field]FieldInfo, len(commonFields)+len(platform))
	for field, info := range commonFields {
		fields[field] = info
	}
	for field, info := range platform {
		fields[field] = info
	}
	return fields
}

// ArgumentOf returns argument data for the specified field.
func ArgumentOf(name string) *Argument {
	f, ok := fields[Field(name)]
	if !ok {
		// this can happen for pseudo fields
		return nil
	}
	return f.Argument
}

// IsField returns true if the provided string is a
// recognized field or pseudo field. Otherwise, it
// returns false.
func IsField(name string) bool {
	if _, ok := fields[Field(name)]; ok || IsPseudoField(Field(name)) {
		return true
	}
	return false
}
