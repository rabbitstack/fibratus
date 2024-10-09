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
	"regexp"
	"strings"

	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
)

// pathRegexp splits the provided path into different components. The first capture
// contains the indexed field name. Next is the indexed key and, finally the segment.
var pathRegexp = regexp.MustCompile(`(pe.sections|pe.resources|ps.envs|ps.modules|ps.ancestor|kevt.arg|thread.callstack)\[(.+\s*)].?(.*)`)

// Field represents the type alias for the field
type Field string

// IsEmpty determines if this field is empty.
func (f Field) IsEmpty() bool { return f == "" }

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
	// PsHandles represents the process handles
	PsHandles Field = "ps.handles"
	// PsHandleTypes represents the process handle types
	PsHandleTypes Field = "ps.handle.types"
	// PsDTB represents the process directory table base address
	PsDTB Field = "ps.dtb"
	// PsModules represents the process modules
	PsModules Field = "ps.modules"
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
	// PsAncestor represents the process ancestor sequence field
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

	// PsSiblingPid represents the sibling process identifier field. Deprecated
	PsSiblingPid Field = "ps.sibling.pid"
	// PsSiblingName represents the sibling process name field. Deprecated
	PsSiblingName Field = "ps.sibling.name"
	// PsSiblingComm represents the sibling process command line field. Deprecated
	PsSiblingComm Field = "ps.sibling.comm"
	// PsSiblingExe represents the sibling process complete executable path field. Deprecated
	PsSiblingExe Field = "ps.sibling.exe"
	// PsSiblingArgs represents the sibling process command line arguments path field. Deprecated
	PsSiblingArgs Field = "ps.sibling.args"
	// PsSiblingSID represents the sibling process security identifier field. Deprecated
	PsSiblingSID Field = "ps.sibling.sid"
	// PsSiblingSessionID represents the sibling process session id field. Deprecated
	PsSiblingSessionID Field = "ps.sibling.sessionid"
	// PsSiblingDomain represents the sibling process domain field. Deprecated
	PsSiblingDomain Field = "ps.sibling.domain"
	// PsSiblingUsername represents the sibling process username field. Deprecated
	PsSiblingUsername Field = "ps.sibling.username"
	// PsUUID represents the unique process identifier
	PsUUID Field = "ps.uuid"
	// PsParentUUID represents the unique parent process identifier
	PsParentUUID Field = "ps.parent.uuid"
	// PsChildUUID represents the unique child process identifier
	PsChildUUID Field = "ps.child.uuid"

	// PsChildPid represents the child process identifier field
	PsChildPid Field = "ps.child.pid"
	// PsChildName represents the child process name field
	PsChildName Field = "ps.child.name"
	// PsChildCmdline represents the child process command line field
	PsChildCmdline Field = "ps.child.cmdline"
	// PsChildExe represents the child process complete executable path field
	PsChildExe Field = "ps.child.exe"
	// PsChildArgs represents the child process command line arguments path field
	PsChildArgs Field = "ps.child.args"
	// PsChildSID represents the child process security identifier field
	PsChildSID Field = "ps.child.sid"
	// PsChildSessionID represents the child process session id field
	PsChildSessionID Field = "ps.child.sessionid"
	// PsChildDomain represents the child process domain field
	PsChildDomain Field = "ps.child.domain"
	// PsChildUsername represents the child process username field
	PsChildUsername Field = "ps.child.username"
	// PsChildPeFilename represents the original file name of the child process executable provided at compile-time
	PsChildPeFilename Field = "ps.child.pe.file.name"
	// PsChildIsWOW64Field  represents the field that indicates if the 32-bit process is created in 64-bit Windows system
	PsChildIsWOW64Field Field = "ps.child.is_wow64"
	// PsChildIsPackagedField represents the field that indicates if a process is packaged with the MSIX technology
	PsChildIsPackagedField Field = "ps.child.is_packaged"
	// PsChildIsProtectedField represents the field that indicates if the process is to be run as a protected process
	PsChildIsProtectedField Field = "ps.child.is_protected"

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
	// ThreadAccessMask represents the thread access rights field
	ThreadAccessMask Field = "thread.access.mask"
	// ThreadAccessMaskNames represents the thread access rights list field
	ThreadAccessMaskNames Field = "thread.access.mask.names"
	// ThreadAccessStatus represents the thread access status field
	ThreadAccessStatus Field = "thread.access.status"
	// ThreadCallstack represents the field that provides access to stack frames
	ThreadCallstack Field = "thread.callstack"
	// ThreadCallstackSummary represents the thread callstack summary field
	ThreadCallstackSummary Field = "thread.callstack.summary"
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

	// PeNumSections represents the number of sections
	PeNumSections Field = "pe.nsections"
	// PeSections represents distinct section inside PE
	PeSections Field = "pe.sections"
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
	// PePsChildFileName represents the original file name of the child process executable provided at compile-time
	PePsChildFileName Field = "pe.ps.child.file.name"

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
	// KevtMeta is the event metadata
	KevtMeta Field = "kevt.meta"
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
	// FileName represents the fie name
	FileName Field = "file.name"
	// FileExtension represents the file extension (e.g. .exe or .dll)
	FileExtension Field = "file.extension"
	// FileOperation represents the file operation (e.g. create)
	FileOperation Field = "file.operation"
	// FileShareMask represents the file share mask
	FileShareMask Field = "file.share.mask"
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
	// FileIsDriverVulnerable represents the field that denotes whether the created file is a vulnerable driver
	FileIsDriverVulnerable Field = "file.is_driver_vulnerable"
	// FileIsDriverMalicious represents the field that denotes whether the created file is a malicious driver
	FileIsDriverMalicious Field = "file.is_driver_malicious"
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

	// RegistryKeyName represents the registry key name
	RegistryKeyName Field = "registry.key.name"
	// RegistryKeyHandle represents the registry KCB address
	RegistryKeyHandle Field = "registry.key.handle"
	// RegistryValue represents the registry value
	RegistryValue Field = "registry.value"
	// RegistryValueType represents the registry value type
	RegistryValueType Field = "registry.value.type"
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
	// ImageName is the module full name
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
	// ImageIsDriverVulnerable represents the field that denotes whether loaded driver is vulnerable
	ImageIsDriverVulnerable Field = "image.is_driver_vulnerable"
	// ImageIsDriverMalicious represents the field that denotes whether the loaded driver is malicious
	ImageIsDriverMalicious Field = "image.is_driver_malicious"
	// ImageIsDLL indicates if the loaded image is a DLL
	ImageIsDLL Field = "image.is_dll"
	// ImageIsDriver indicates if the loaded image is a driver
	ImageIsDriver Field = "image.is_driver"
	// ImageIsExecutable indicates if the loaded image is an executable
	ImageIsExecutable Field = "image.is_exec"
	// ImageIsDotnet indicates if the loaded image is a .NET assembly
	ImageIsDotnet Field = "image.is_dotnet"

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

	// None represents the unknown field
	None Field = ""
)

// String casts the field type to string.
func (f Field) String() string { return string(f) }

func (f Field) IsPsField() bool       { return strings.HasPrefix(string(f), "ps.") }
func (f Field) IsKevtField() bool     { return strings.HasPrefix(string(f), "kevt.") }
func (f Field) IsThreadField() bool   { return strings.HasPrefix(string(f), "thread.") }
func (f Field) IsImageField() bool    { return strings.HasPrefix(string(f), "image.") }
func (f Field) IsFileField() bool     { return strings.HasPrefix(string(f), "file.") }
func (f Field) IsRegistryField() bool { return strings.HasPrefix(string(f), "registry.") }
func (f Field) IsNetworkField() bool  { return strings.HasPrefix(string(f), "net.") }
func (f Field) IsHandleField() bool   { return strings.HasPrefix(string(f), "handle.") }
func (f Field) IsPeField() bool       { return strings.HasPrefix(string(f), "pe.") || f == PsChildPeFilename }
func (f Field) IsMemField() bool      { return strings.HasPrefix(string(f), "mem.") }
func (f Field) IsDNSField() bool      { return strings.HasPrefix(string(f), "dns.") }

func (f Field) IsPeSection() bool { return f == PeNumSections }
func (f Field) IsPeSectionEntropy() bool {
	fld := string(f)
	return strings.HasPrefix(fld, "pe.sections[") && strings.HasSuffix(fld, ".entropy")
}
func (f Field) IsPeSymbol() bool { return f == PeSymbols || f == PeNumSymbols || f == PeImports }
func (f Field) IsPeVersionResource() bool {
	return f == PeCompany || f == PeCopyright || f == PeDescription || f == PeFileName || f == PeFileVersion || f == PeProduct || f == PeProductVersion || f == PePsChildFileName || f == PsChildPeFilename
}
func (f Field) IsPeImphash() bool   { return f == PeImphash }
func (f Field) IsPeDotnet() bool    { return f == PeIsDotnet }
func (f Field) IsPeAnomalies() bool { return f == PeAnomalies }
func (f Field) IsPeSignature() bool {
	return f == PeIsTrusted || f == PeIsSigned || f == PeCertIssuer || f == PeCertSerial || f == PeCertSubject || f == PeCertBefore || f == PeCertAfter
}
func (f Field) IsPeIsTrusted() bool { return f == PeIsTrusted }
func (f Field) IsPeIsSigned() bool  { return f == PeIsSigned }

func (f Field) IsPeCert() bool    { return strings.HasPrefix(string(f), "pe.cert.") }
func (f Field) IsImageCert() bool { return strings.HasPrefix(string(f), "image.cert.") }

func (f Field) IsPeModified() bool { return f == PeIsModified }

// Segment represents the type alias for the segment. Segment
// denotes the location of the value within an indexed field.
type Segment string

const (
	// SectionEntropy is the entropy value of the specific PE section
	SectionEntropy Segment = "entropy"
	// SectionMD5Hash refers to the section md5 sum
	SectionMD5Hash Segment = "md5"
	// SectionSize is the section size
	SectionSize Segment = "size"

	// ModuleSize is the module size
	ModuleSize Segment = "size"
	// ModuleChecksum is the module checksum
	ModuleChecksum Segment = "checksum"
	// ModuleLocation is the module location
	ModuleLocation Segment = "location"
	// ModuleBaseAddress is the module base address
	ModuleBaseAddress Segment = "address.base"
	// ModuleDefaultAddress is the module address
	ModuleDefaultAddress Segment = "address.default"

	// ProcessID represents the process id
	ProcessID Segment = "pid"
	// ProcessName represents the process name
	ProcessName Segment = "name"
	// ProcessCmdline represents the process command line
	ProcessCmdline Segment = "cmdline"
	// ProcessExe represents the process image path
	ProcessExe Segment = "exe"
	// ProcessArgs represents the process command line arguments
	ProcessArgs Segment = "args"
	// ProcessCwd represents the process current working directory
	ProcessCwd Segment = "cwd"
	// ProcessSID represents the process security identifier
	ProcessSID Segment = "sid"
	// ProcessSessionID represents the session id bound to the process
	ProcessSessionID Segment = "sessionid"

	// FrameAddress represents the stack frame return address
	FrameAddress Segment = "address"
	// FrameSymbolOffset represents the symbol offset
	FrameSymbolOffset Segment = "offset"
	// FrameSymbol represents the symbol name
	FrameSymbol Segment = "symbol"
	// FrameModule represents the symbol module
	FrameModule Segment = "module"
	// FrameAllocationSize represents the frame region allocation size
	FrameAllocationSize Segment = "allocation_size"
	// FrameProtection represents the region page protection where the frame instruction lives
	FrameProtection Segment = "protection"
	// FrameIsUnbacked determines if the frame is unbacked
	FrameIsUnbacked Segment = "is_unbacked"
	// FrameCallsiteLeadingAssembly represents the leading callsite opcodes
	FrameCallsiteLeadingAssembly = "callsite_leading_assembly"
	// FrameCallsiteTrailingAssembly represents the trailing callsite opcodes
	FrameCallsiteTrailingAssembly = "callsite_trailing_assembly"
)

func (s Segment) IsSection() bool {
	return s == SectionEntropy || s == SectionSize || s == SectionMD5Hash
}
func (s Segment) IsModule() bool {
	return s == ModuleChecksum || s == ModuleLocation || s == ModuleBaseAddress || s == ModuleDefaultAddress || s == ModuleSize
}
func (s Segment) IsProcess() bool {
	return s == ProcessID || s == ProcessName || s == ProcessCmdline || s == ProcessExe || s == ProcessArgs || s == ProcessCwd || s == ProcessSID || s == ProcessSessionID
}
func (s Segment) IsCallstack() bool {
	return s == FrameAddress || s == FrameSymbolOffset || s == FrameSymbol || s == FrameModule || s == FrameAllocationSize || s == FrameProtection || s == FrameIsUnbacked || s == FrameCallsiteLeadingAssembly || s == FrameCallsiteTrailingAssembly
}

func (f Field) IsEnvsMap() bool        { return strings.HasPrefix(f.String(), "ps.envs[") }
func (f Field) IsModsMap() bool        { return strings.HasPrefix(f.String(), "ps.modules[") }
func (f Field) IsAncestorMap() bool    { return strings.HasPrefix(f.String(), "ps.ancestor[") }
func (f Field) IsPeSectionsMap() bool  { return strings.HasPrefix(f.String(), "pe.sections[") }
func (f Field) IsPeResourcesMap() bool { return strings.HasPrefix(f.String(), "pe.resources[") }
func (f Field) IsKevtArgMap() bool     { return strings.HasPrefix(f.String(), "kevt.arg[") }
func (f Field) IsCallstackMap() bool   { return strings.HasPrefix(f.String(), "thread.callstack[") }

var fields = map[Field]FieldInfo{
	KevtSeq:         {KevtSeq, "event sequence number", kparams.Uint64, []string{"kevt.seq > 666"}, nil},
	KevtPID:         {KevtPID, "process identifier generating the kernel event", kparams.Uint32, []string{"kevt.pid = 6"}, nil},
	KevtTID:         {KevtTID, "thread identifier generating the kernel event", kparams.Uint32, []string{"kevt.tid = 1024"}, nil},
	KevtCPU:         {KevtCPU, "logical processor core where the event was generated", kparams.Uint8, []string{"kevt.cpu = 2"}, nil},
	KevtName:        {KevtName, "symbolical kernel event name", kparams.AnsiString, []string{"kevt.name = 'CreateThread'"}, nil},
	KevtCategory:    {KevtCategory, "event category", kparams.AnsiString, []string{"kevt.category = 'registry'"}, nil},
	KevtDesc:        {KevtDesc, "event description", kparams.AnsiString, []string{"kevt.desc contains 'Creates a new process'"}, nil},
	KevtHost:        {KevtHost, "host name on which the event was produced", kparams.UnicodeString, []string{"kevt.host contains 'kitty'"}, nil},
	KevtTime:        {KevtTime, "event timestamp as a time string", kparams.Time, []string{"kevt.time = '17:05:32'"}, nil},
	KevtTimeHour:    {KevtTimeHour, "hour within the day on which the event occurred", kparams.Time, []string{"kevt.time.h = 23"}, nil},
	KevtTimeMin:     {KevtTimeMin, "minute offset within the hour on which the event occurred", kparams.Time, []string{"kevt.time.m = 54"}, nil},
	KevtTimeSec:     {KevtTimeSec, "second offset within the minute  on which the event occurred", kparams.Time, []string{"kevt.time.s = 0"}, nil},
	KevtTimeNs:      {KevtTimeNs, "nanoseconds specified by event timestamp", kparams.Int64, []string{"kevt.time.ns > 1591191629102337000"}, nil},
	KevtDate:        {KevtDate, "event timestamp as a date string", kparams.Time, []string{"kevt.date = '2018-03-03'"}, nil},
	KevtDateDay:     {KevtDateDay, "day of the month on which the event occurred", kparams.Time, []string{"kevt.date.d = 12"}, nil},
	KevtDateMonth:   {KevtDateMonth, "month of the year on which the event occurred", kparams.Time, []string{"kevt.date.m = 11"}, nil},
	KevtDateYear:    {KevtDateYear, "year on which the event occurred", kparams.Uint32, []string{"kevt.date.y = 2020"}, nil},
	KevtDateTz:      {KevtDateTz, "time zone associated with the event timestamp", kparams.AnsiString, []string{"kevt.date.tz = 'UTC'"}, nil},
	KevtDateWeek:    {KevtDateWeek, "week number within the year on which the event occurred", kparams.Uint8, []string{"kevt.date.week = 2"}, nil},
	KevtDateWeekday: {KevtDateWeekday, "week day on which the event occurred", kparams.AnsiString, []string{"kevt.date.weekday = 'Monday'"}, nil},
	KevtNparams:     {KevtNparams, "number of parameters", kparams.Int8, []string{"kevt.nparams > 2"}, nil},

	PsPid:                    {PsPid, "process identifier", kparams.PID, []string{"ps.pid = 1024"}, nil},
	PsPpid:                   {PsPpid, "parent process identifier", kparams.PID, []string{"ps.ppid = 45"}, nil},
	PsName:                   {PsName, "process image name including the file extension", kparams.UnicodeString, []string{"ps.name contains 'firefox'"}, nil},
	PsComm:                   {PsComm, "process command line", kparams.UnicodeString, []string{"ps.comm contains 'java'"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsCmdline}}},
	PsCmdline:                {PsCmdline, "process command line", kparams.UnicodeString, []string{"ps.cmdline contains 'java'"}, nil},
	PsExe:                    {PsExe, "full name of the process' executable", kparams.UnicodeString, []string{"ps.exe = 'C:\\Windows\\system32\\cmd.exe'"}, nil},
	PsArgs:                   {PsArgs, "process command line arguments", kparams.Slice, []string{"ps.args in ('/cdir', '/-C')"}, nil},
	PsCwd:                    {PsCwd, "process current working directory", kparams.UnicodeString, []string{"ps.cwd = 'C:\\Users\\Default'"}, nil},
	PsSID:                    {PsSID, "security identifier under which this process is run", kparams.UnicodeString, []string{"ps.sid contains 'SYSTEM'"}, nil},
	PsSessionID:              {PsSessionID, "unique identifier for the current session", kparams.Int16, []string{"ps.sessionid = 1"}, nil},
	PsDomain:                 {PsDomain, "process domain", kparams.UnicodeString, []string{"ps.domain contains 'SERVICE'"}, nil},
	PsUsername:               {PsUsername, "process username", kparams.UnicodeString, []string{"ps.username contains 'system'"}, nil},
	PsEnvs:                   {PsEnvs, "process environment variables", kparams.Slice, []string{"ps.envs in ('MOZ_CRASHREPORTER_DATA_DIRECTORY')"}, nil},
	PsHandles:                {PsHandles, "allocated process handle names", kparams.Slice, []string{"ps.handles in ('\\BaseNamedObjects\\__ComCatalogCache__')"}, nil},
	PsHandleTypes:            {PsHandleTypes, "allocated process handle types", kparams.Slice, []string{"ps.handle.types in ('Key', 'Mutant', 'Section')"}, nil},
	PsDTB:                    {PsDTB, "process directory table base address", kparams.Address, []string{"ps.dtb = '7ffe0000'"}, nil},
	PsModules:                {PsModules, "modules loaded by the process", kparams.Slice, []string{"ps.modules in ('crypt32.dll', 'xul.dll')"}, nil},
	PsParentName:             {PsParentName, "parent process image name including the file extension", kparams.UnicodeString, []string{"ps.parent.name contains 'cmd.exe'"}, nil},
	PsParentPid:              {PsParentPid, "parent process id", kparams.Uint32, []string{"ps.parent.pid = 4"}, nil},
	PsParentComm:             {PsParentComm, "parent process command line", kparams.UnicodeString, []string{"ps.parent.comm contains 'java'"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsParentCmdline}}},
	PsParentCmdline:          {PsParentCmdline, "parent process command line", kparams.UnicodeString, []string{"ps.parent.cmdline contains 'java'"}, nil},
	PsParentExe:              {PsParentExe, "full name of the parent process' executable", kparams.UnicodeString, []string{"ps.parent.exe = 'C:\\Windows\\system32\\explorer.exe'"}, nil},
	PsParentArgs:             {PsParentArgs, "parent process command line arguments", kparams.Slice, []string{"ps.parent.args in ('/cdir', '/-C')"}, nil},
	PsParentCwd:              {PsParentCwd, "parent process current working directory", kparams.UnicodeString, []string{"ps.parent.cwd = 'C:\\Temp'"}, nil},
	PsParentSID:              {PsParentSID, "security identifier under which the parent process is run", kparams.UnicodeString, []string{"ps.parent.sid contains 'SYSTEM'"}, nil},
	PsParentDomain:           {PsParentDomain, "parent process domain", kparams.UnicodeString, []string{"ps.parent.domain contains 'SERVICE'"}, nil},
	PsParentUsername:         {PsParentUsername, "parent process username", kparams.UnicodeString, []string{"ps.parent.username contains 'system'"}, nil},
	PsParentSessionID:        {PsParentSessionID, "unique identifier for the current session of parent process", kparams.Int16, []string{"ps.parent.sessionid = 1"}, nil},
	PsParentEnvs:             {PsParentEnvs, "parent process environment variables", kparams.Slice, []string{"ps.parent.envs in ('MOZ_CRASHREPORTER_DATA_DIRECTORY')"}, nil},
	PsParentHandles:          {PsParentHandles, "allocated parent process handle names", kparams.Slice, []string{"ps.parent.handles in ('\\BaseNamedObjects\\__ComCatalogCache__')"}, nil},
	PsParentHandleTypes:      {PsParentHandleTypes, "allocated parent process handle types", kparams.Slice, []string{"ps.parent.handle.types in ('File', 'SymbolicLink')"}, nil},
	PsParentDTB:              {PsParentDTB, "parent process directory table base address", kparams.Address, []string{"ps.parent.dtb = '7ffe0000'"}, nil},
	PsAccessMask:             {PsAccessMask, "process desired access rights", kparams.AnsiString, []string{"ps.access.mask = '0x1400'"}, nil},
	PsAccessMaskNames:        {PsAccessMaskNames, "process desired access rights as a string list", kparams.Slice, []string{"ps.access.mask.names in ('SUSPEND_RESUME')"}, nil},
	PsAccessStatus:           {PsAccessStatus, "process access status", kparams.UnicodeString, []string{"ps.access.status = 'access is denied.'"}, nil},
	PsSiblingPid:             {PsSiblingPid, "created or terminated process identifier", kparams.PID, []string{"ps.sibling.pid = 320"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsChildPid}}},
	PsChildPid:               {PsChildPid, "created or terminated process identifier", kparams.PID, []string{"ps.child.pid = 320"}, nil},
	PsSiblingName:            {PsSiblingName, "created or terminated process name", kparams.UnicodeString, []string{"ps.sibling.name = 'notepad.exe'"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsChildName}}},
	PsChildName:              {PsChildName, "created or terminated process name", kparams.UnicodeString, []string{"ps.child.name = 'notepad.exe'"}, nil},
	PsSiblingComm:            {PsSiblingComm, "created or terminated process command line", kparams.UnicodeString, []string{"ps.sibling.comm contains '\\k \\v'"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsChildCmdline}}},
	PsChildCmdline:           {PsChildCmdline, "created or terminated process command line", kparams.UnicodeString, []string{"ps.child.cmdline contains '\\k \\v'"}, nil},
	PsSiblingArgs:            {PsSiblingArgs, "created process command line arguments", kparams.Slice, []string{"ps.sibling.args in ('/cdir', '/-C')"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsChildArgs}}},
	PsChildArgs:              {PsChildArgs, "created process command line arguments", kparams.Slice, []string{"ps.child.args in ('/cdir', '/-C')"}, nil},
	PsSiblingExe:             {PsSiblingExe, "created, terminated, or opened process id", kparams.UnicodeString, []string{"ps.sibling.exe contains '\\Windows\\cmd.exe'"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsChildExe}}},
	PsChildExe:               {PsChildExe, "created, terminated, or opened process id", kparams.UnicodeString, []string{"ps.child.exe contains '\\Windows\\cmd.exe'"}, nil},
	PsSiblingSID:             {PsSiblingSID, "created or terminated process security identifier", kparams.UnicodeString, []string{"ps.sibling.sid contains 'SERVICE'"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsChildSID}}},
	PsChildSID:               {PsChildSID, "created or terminated process security identifier", kparams.UnicodeString, []string{"ps.child.sid contains 'SERVICE'"}, nil},
	PsSiblingSessionID:       {PsSiblingSessionID, "created or terminated process session identifier", kparams.Int16, []string{"ps.sibling.sessionid == 1"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsChildSessionID}}},
	PsChildSessionID:         {PsChildSessionID, "created or terminated process session identifier", kparams.Int16, []string{"ps.child.sessionid == 1"}, nil},
	PsSiblingDomain:          {PsSiblingDomain, "created or terminated process domain", kparams.UnicodeString, []string{"ps.sibling.domain contains 'SERVICE'"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsChildDomain}}},
	PsChildDomain:            {PsChildDomain, "created or terminated process domain", kparams.UnicodeString, []string{"ps.child.domain contains 'SERVICE'"}, nil},
	PsSiblingUsername:        {PsSiblingUsername, "created or terminated process username", kparams.UnicodeString, []string{"ps.sibling.username contains 'system'"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsChildUsername}}},
	PsChildUsername:          {PsChildUsername, "created or terminated process username", kparams.UnicodeString, []string{"ps.child.username contains 'system'"}, nil},
	PsUUID:                   {PsUUID, "unique process identifier", kparams.Uint64, []string{"ps.uuid > 6000054355"}, nil},
	PsParentUUID:             {PsParentUUID, "unique parent process identifier", kparams.Uint64, []string{"ps.parent.uuid > 6000054355"}, nil},
	PsChildUUID:              {PsChildUUID, "unique child process identifier", kparams.Uint64, []string{"ps.child.uuid > 6000054355"}, nil},
	PsChildPeFilename:        {PsChildPeFilename, "original file name of the child process executable supplied at compile-time", kparams.UnicodeString, []string{"ps.child.pe.file.name = 'NOTEPAD.EXE'"}, nil},
	PsChildIsWOW64Field:      {PsChildIsWOW64Field, "indicates if the 32-bit child process is created in 64-bit Windows system", kparams.Bool, []string{"ps.child.is_wow64"}, nil},
	PsChildIsPackagedField:   {PsChildIsPackagedField, "indicates if the child process is packaged with the MSIX technology", kparams.Bool, []string{"ps.child.is_packaged"}, nil},
	PsChildIsProtectedField:  {PsChildIsProtectedField, "indicates if the child process is a protected process", kparams.Bool, []string{"ps.child.is_protected"}, nil},
	PsIsWOW64Field:           {PsIsWOW64Field, "indicates if the process generating the event is a 32-bit process created in 64-bit Windows system", kparams.Bool, []string{"ps.is_wow64"}, nil},
	PsIsPackagedField:        {PsIsPackagedField, "indicates if the process generating the event is packaged with the MSIX technology", kparams.Bool, []string{"ps.is_packaged"}, nil},
	PsIsProtectedField:       {PsIsProtectedField, "indicates if the process generating the event is a protected process", kparams.Bool, []string{"ps.is_protected"}, nil},
	PsParentIsWOW64Field:     {PsParentIsWOW64Field, "indicates if the parent process generating the event is a 32-bit process created in 64-bit Windows system", kparams.Bool, []string{"ps.parent.is_wow64"}, nil},
	PsParentIsPackagedField:  {PsParentIsPackagedField, "indicates if the parent process generating the event is packaged with the MSIX technology", kparams.Bool, []string{"ps.parent.is_packaged"}, nil},
	PsParentIsProtectedField: {PsParentIsProtectedField, "indicates if the the parent process generating the event is a protected process", kparams.Bool, []string{"ps.parent.is_protected"}, nil},

	ThreadBasePrio:                          {ThreadBasePrio, "scheduler priority of the thread", kparams.Int8, []string{"thread.prio = 5"}, nil},
	ThreadIOPrio:                            {ThreadIOPrio, "I/O priority hint for scheduling I/O operations", kparams.Int8, []string{"thread.io.prio = 4"}, nil},
	ThreadPagePrio:                          {ThreadPagePrio, "memory page priority hint for memory pages accessed by the thread", kparams.Int8, []string{"thread.page.prio = 12"}, nil},
	ThreadKstackBase:                        {ThreadKstackBase, "base address of the thread's kernel space stack", kparams.Address, []string{"thread.kstack.base = 'a65d800000'"}, nil},
	ThreadKstackLimit:                       {ThreadKstackLimit, "limit of the thread's kernel space stack", kparams.Address, []string{"thread.kstack.limit = 'a85d800000'"}, nil},
	ThreadUstackBase:                        {ThreadUstackBase, "base address of the thread's user space stack", kparams.Address, []string{"thread.ustack.base = '7ffe0000'"}, nil},
	ThreadUstackLimit:                       {ThreadUstackLimit, "limit of the thread's user space stack", kparams.Address, []string{"thread.ustack.limit = '8ffe0000'"}, nil},
	ThreadEntrypoint:                        {ThreadEntrypoint, "starting address of the function to be executed by the thread", kparams.Address, []string{"thread.entrypoint = '7efe0000'"}, &Deprecation{Since: "2.3.0", Fields: []Field{ThreadStartAddress}}},
	ThreadStartAddress:                      {ThreadStartAddress, "thread start address", kparams.Address, []string{"thread.start_address = '7efe0000'"}, nil},
	ThreadPID:                               {ThreadPID, "the process identifier where the thread is created", kparams.Uint32, []string{"kevt.pid != thread.pid"}, nil},
	ThreadAccessMask:                        {ThreadAccessMask, "thread desired access rights", kparams.AnsiString, []string{"thread.access.mask = '0x1fffff'"}, nil},
	ThreadAccessMaskNames:                   {ThreadAccessMaskNames, "thread desired access rights as a string list", kparams.Slice, []string{"thread.access.mask.names in ('IMPERSONATE')"}, nil},
	ThreadAccessStatus:                      {ThreadAccessStatus, "thread access status", kparams.UnicodeString, []string{"thread.access.status = 'success'"}, nil},
	ThreadCallstackSummary:                  {ThreadCallstackSummary, "callstack summary", kparams.UnicodeString, []string{"thread.callstack.summary contains 'ntdll.dll|KERNELBASE.dll'"}, nil},
	ThreadCallstackDetail:                   {ThreadCallstackDetail, "detailed information of each stack frame", kparams.UnicodeString, []string{"thread.callstack.detail contains 'KERNELBASE.dll!CreateProcessW'"}, nil},
	ThreadCallstackModules:                  {ThreadCallstackModules, "list of modules comprising the callstack", kparams.Slice, []string{"thread.callstack.modules in ('C:\\WINDOWS\\System32\\KERNELBASE.dll')"}, nil},
	ThreadCallstackSymbols:                  {ThreadCallstackSymbols, "list of symbols comprising the callstack", kparams.Slice, []string{"thread.callstack.symbols in ('ntdll.dll!NtCreateProcess')"}, nil},
	ThreadCallstackAllocationSizes:          {ThreadCallstackAllocationSizes, "allocation sizes of private pages", kparams.Slice, []string{"thread.callstack.allocation_sizes > 10000"}, nil},
	ThreadCallstackProtections:              {ThreadCallstackProtections, "page protections masks of each frame", kparams.Slice, []string{"thread.callstack.protections in ('RWX', 'WX')"}, nil},
	ThreadCallstackCallsiteLeadingAssembly:  {ThreadCallstackCallsiteLeadingAssembly, "callsite leading assembly instructions", kparams.Slice, []string{"thread.callstack.callsite_leading_assembly in ('mov r10,rcx', 'syscall')"}, nil},
	ThreadCallstackCallsiteTrailingAssembly: {ThreadCallstackCallsiteTrailingAssembly, "callsite trailing assembly instructions", kparams.Slice, []string{"thread.callstack.callsite_trailing_assembly in ('add esp, 0xab')"}, nil},
	ThreadCallstackIsUnbacked:               {ThreadCallstackIsUnbacked, "indicates if the callstack contains unbacked regions", kparams.Bool, []string{"thread.callstack.is_unbacked"}, nil},

	ImageName:               {ImageName, "full image name", kparams.UnicodeString, []string{"image.name contains 'advapi32.dll'"}, nil},
	ImageBase:               {ImageBase, "the base address of process in which the image is loaded", kparams.Address, []string{"image.base.address = 'a65d800000'"}, nil},
	ImageChecksum:           {ImageChecksum, "image checksum", kparams.Uint32, []string{"image.checksum = 746424"}, nil},
	ImageSize:               {ImageSize, "image size", kparams.Uint32, []string{"image.size > 1024"}, nil},
	ImageDefaultAddress:     {ImageDefaultAddress, "default image address", kparams.Address, []string{"image.default.address = '7efe0000'"}, nil},
	ImagePID:                {ImagePID, "target process identifier", kparams.Uint32, []string{"image.pid = 80"}, nil},
	ImageSignatureType:      {ImageSignatureType, "image signature type", kparams.AnsiString, []string{"image.signature.type != 'NONE'"}, nil},
	ImageSignatureLevel:     {ImageSignatureLevel, "image signature level", kparams.AnsiString, []string{"image.signature.level = 'AUTHENTICODE'"}, nil},
	ImageCertSerial:         {ImageCertSerial, "image certificate serial number", kparams.UnicodeString, []string{"image.cert.serial = '330000023241fb59996dcc4dff000000000232'"}, nil},
	ImageCertSubject:        {ImageCertSubject, "image certificate subject", kparams.UnicodeString, []string{"image.cert.subject contains 'Washington, Redmond, Microsoft Corporation'"}, nil},
	ImageCertIssuer:         {ImageCertIssuer, "image certificate CA", kparams.UnicodeString, []string{"image.cert.issuer contains 'Washington, Redmond, Microsoft Corporation'"}, nil},
	ImageCertAfter:          {ImageCertAfter, "image certificate expiration date", kparams.Time, []string{"image.cert.after contains '2024-02-01 00:05:42 +0000 UTC'"}, nil},
	ImageCertBefore:         {ImageCertBefore, "image certificate enrollment date", kparams.Time, []string{"image.cert.before contains '2024-02-01 00:05:42 +0000 UTC'"}, nil},
	ImageIsDriverMalicious:  {ImageIsDriverMalicious, "indicates if the loaded driver is malicious", kparams.Bool, []string{"image.is_driver_malicious"}, nil},
	ImageIsDriverVulnerable: {ImageIsDriverVulnerable, "indicates if the loaded driver is vulnerable", kparams.Bool, []string{"image.is_driver_vulnerable"}, nil},
	ImageIsDLL:              {ImageIsDLL, "indicates if the loaded image is a DLL", kparams.Bool, []string{"image.is_dll'"}, nil},
	ImageIsDriver:           {ImageIsDriver, "indicates if the loaded image is a driver", kparams.Bool, []string{"image.is_driver'"}, nil},
	ImageIsExecutable:       {ImageIsExecutable, "indicates if the loaded image is an executable", kparams.Bool, []string{"image.is_exec'"}, nil},
	ImageIsDotnet:           {ImageIsDotnet, "indicates if the loaded image is a .NET assembly", kparams.Bool, []string{"image.is_dotnet'"}, nil},

	FileObject:             {FileObject, "file object address", kparams.Uint64, []string{"file.object = 18446738026482168384"}, nil},
	FileName:               {FileName, "full file name", kparams.UnicodeString, []string{"file.name contains 'mimikatz'"}, nil},
	FileOperation:          {FileOperation, "file operation", kparams.AnsiString, []string{"file.operation = 'open'"}, nil},
	FileShareMask:          {FileShareMask, "file share mask", kparams.AnsiString, []string{"file.share.mask = 'rw-'"}, nil},
	FileIOSize:             {FileIOSize, "file I/O size", kparams.Uint32, []string{"file.io.size > 512"}, nil},
	FileOffset:             {FileOffset, "file offset", kparams.Uint64, []string{"file.offset = 1024"}, nil},
	FileType:               {FileType, "file type", kparams.AnsiString, []string{"file.type = 'directory'"}, nil},
	FileExtension:          {FileExtension, "file extension", kparams.AnsiString, []string{"file.extension = '.dll'"}, nil},
	FileAttributes:         {FileAttributes, "file attributes", kparams.Slice, []string{"file.attributes in ('archive', 'hidden')"}, nil},
	FileStatus:             {FileStatus, "file operation status message", kparams.UnicodeString, []string{"file.status != 'success'"}, nil},
	FileViewBase:           {FileViewBase, "view base address", kparams.Address, []string{"file.view.base = '25d42170000'"}, nil},
	FileViewSize:           {FileViewSize, "size of the mapped view", kparams.Uint64, []string{"file.view.size > 1024"}, nil},
	FileViewType:           {FileViewType, "type of the mapped view section", kparams.Enum, []string{"file.view.type = 'IMAGE'"}, nil},
	FileViewProtection:     {FileViewProtection, "protection rights of the section view", kparams.AnsiString, []string{"file.view.protection = 'READONLY'"}, nil},
	FileIsDriverMalicious:  {FileIsDriverMalicious, "indicates if the dropped driver is malicious", kparams.Bool, []string{"file.is_driver_malicious"}, nil},
	FileIsDriverVulnerable: {FileIsDriverVulnerable, "indicates if the dropped driver is vulnerable", kparams.Bool, []string{"file.is_driver_vulnerable"}, nil},
	FileIsDLL:              {FileIsDLL, "indicates if the created file is a DLL", kparams.Bool, []string{"file.is_dll'"}, nil},
	FileIsDriver:           {FileIsDriver, "indicates if the created file is a driver", kparams.Bool, []string{"file.is_driver'"}, nil},
	FileIsExecutable:       {FileIsExecutable, "indicates if the created file is an executable", kparams.Bool, []string{"file.is_exec'"}, nil},
	FilePID:                {FilePID, "denotes the process id performing file operation", kparams.PID, []string{"file.pid = 4"}, nil},
	FileKey:                {FileKey, "uniquely identifies the file object", kparams.Uint64, []string{"file.key = 12446738026482168384"}, nil},

	RegistryKeyName:   {RegistryKeyName, "fully qualified key name", kparams.UnicodeString, []string{"registry.key.name contains 'HKEY_LOCAL_MACHINE'"}, nil},
	RegistryKeyHandle: {RegistryKeyHandle, "registry key object address", kparams.Address, []string{"registry.key.handle = 'FFFFB905D60C2268'"}, nil},
	RegistryValue:     {RegistryValue, "registry value content", kparams.UnicodeString, []string{"registry.value = '%SystemRoot%\\system32'"}, nil},
	RegistryValueType: {RegistryValueType, "type of registry value", kparams.UnicodeString, []string{"registry.value.type = 'REG_SZ'"}, nil},
	RegistryStatus:    {RegistryStatus, "status of registry operation", kparams.UnicodeString, []string{"registry.status != 'success'"}, nil},

	NetDIP:        {NetDIP, "destination IP address", kparams.IP, []string{"net.dip = 172.17.0.3"}, nil},
	NetSIP:        {NetSIP, "source IP address", kparams.IP, []string{"net.sip = 127.0.0.1"}, nil},
	NetDport:      {NetDport, "destination port", kparams.Uint16, []string{"net.dport in (80, 443, 8080)"}, nil},
	NetSport:      {NetSport, "source port", kparams.Uint16, []string{"net.sport != 3306"}, nil},
	NetDportName:  {NetDportName, "destination port name", kparams.AnsiString, []string{"net.dport.name = 'dns'"}, nil},
	NetSportName:  {NetSportName, "source port name", kparams.AnsiString, []string{"net.sport.name = 'http'"}, nil},
	NetL4Proto:    {NetL4Proto, "layer 4 protocol name", kparams.AnsiString, []string{"net.l4.proto = 'TCP"}, nil},
	NetPacketSize: {NetPacketSize, "packet size", kparams.Uint32, []string{"net.size > 512"}, nil},
	NetSIPNames:   {NetSIPNames, "source IP names", kparams.Slice, []string{"net.sip.names in ('github.com.')"}, nil},
	NetDIPNames:   {NetDIPNames, "destination IP names", kparams.Slice, []string{"net.dip.names in ('github.com.')"}, nil},

	HandleID:     {HandleID, "handle identifier", kparams.Uint16, []string{"handle.id = 24"}, nil},
	HandleObject: {HandleObject, "handle object address", kparams.Address, []string{"handle.object = 'FFFFB905DBF61988'"}, nil},
	HandleName:   {HandleName, "handle name", kparams.UnicodeString, []string{"handle.name = '\\Device\\NamedPipe\\chrome.12644.28.105826381'"}, nil},
	HandleType:   {HandleType, "handle type", kparams.AnsiString, []string{"handle.type = 'Mutant'"}, nil},

	PeNumSections:     {PeNumSections, "number of sections", kparams.Uint16, []string{"pe.nsections < 5"}, nil},
	PeNumSymbols:      {PeNumSymbols, "number of entries in the symbol table", kparams.Uint32, []string{"pe.nsymbols > 230"}, nil},
	PeBaseAddress:     {PeBaseAddress, "image base address", kparams.Address, []string{"pe.address.base = '140000000'"}, nil},
	PeEntrypoint:      {PeEntrypoint, "address of the entrypoint function", kparams.Address, []string{"pe.address.entrypoint = '20110'"}, nil},
	PeSections:        {PeSections, "PE sections", kparams.Object, []string{"pe.sections[.text].entropy > 6.2"}, nil},
	PeSymbols:         {PeSymbols, "imported symbols", kparams.Slice, []string{"pe.symbols in ('GetTextFaceW', 'GetProcessHeap')"}, nil},
	PeImports:         {PeImports, "imported dynamic linked libraries", kparams.Slice, []string{"pe.imports in ('msvcrt.dll', 'GDI32.dll'"}, nil},
	PeResources:       {PeResources, "version and other resources", kparams.Map, []string{"pe.resources[FileDescription] = 'Notepad'"}, nil},
	PeCompany:         {PeCompany, "internal company name of the file provided at compile-time", kparams.UnicodeString, []string{"pe.company = 'Microsoft Corporation'"}, nil},
	PeCopyright:       {PeCopyright, "copyright notice for the file emitted at compile-time", kparams.UnicodeString, []string{"pe.copyright = '© Microsoft Corporation'"}, nil},
	PeDescription:     {PeDescription, "internal description of the file provided at compile-time", kparams.UnicodeString, []string{"pe.description = 'Notepad'"}, nil},
	PeFileName:        {PeFileName, "original file name supplied at compile-time", kparams.UnicodeString, []string{"pe.file.name = 'NOTEPAD.EXE'"}, nil},
	PeFileVersion:     {PeFileVersion, "file version supplied at compile-time", kparams.UnicodeString, []string{"pe.file.version = '10.0.18362.693 (WinBuild.160101.0800)'"}, nil},
	PeProduct:         {PeProduct, "internal product name of the file provided at compile-time", kparams.UnicodeString, []string{"pe.product = 'Microsoft® Windows® Operating System'"}, nil},
	PeProductVersion:  {PeProductVersion, "internal product version of the file provided at compile-time", kparams.UnicodeString, []string{"pe.product.version = '10.0.18362.693'"}, nil},
	PeIsDLL:           {PeIsDLL, "indicates if the loaded image or created file is a DLL", kparams.Bool, []string{"pe.is_dll'"}, &Deprecation{Since: "2.0.0", Fields: []Field{FileIsDLL, ImageIsDLL}}},
	PeIsDriver:        {PeIsDriver, "indicates if the loaded image or created file is a driver", kparams.Bool, []string{"pe.is_driver'"}, &Deprecation{Since: "2.0.0", Fields: []Field{FileIsDriver, ImageIsDriver}}},
	PeIsExecutable:    {PeIsExecutable, "indicates if the loaded image or created file is an executable", kparams.Bool, []string{"pe.is_exec'"}, &Deprecation{Since: "2.0.0", Fields: []Field{FileIsExecutable, ImageIsExecutable}}},
	PeImphash:         {PeImphash, "import hash", kparams.AnsiString, []string{"pe.impash = '5d3861c5c547f8a34e471ba273a732b2'"}, nil},
	PeIsDotnet:        {PeIsDotnet, "indicates if PE contains CLR data", kparams.Bool, []string{"pe.is_dotnet"}, nil},
	PeAnomalies:       {PeAnomalies, "contains PE anomalies detected during parsing", kparams.Slice, []string{"pe.anomalies in ('number of sections is 0')"}, nil},
	PeIsSigned:        {PeIsSigned, "indicates if the PE has embedded or catalog signature", kparams.Bool, []string{"pe.is_signed"}, nil},
	PeIsTrusted:       {PeIsTrusted, "indicates if the PE certificate chain is trusted", kparams.Bool, []string{"pe.is_trusted"}, nil},
	PeCertSerial:      {PeCertSerial, "PE certificate serial number", kparams.UnicodeString, []string{"pe.cert.serial = '330000023241fb59996dcc4dff000000000232'"}, nil},
	PeCertSubject:     {PeCertSubject, "PE certificate subject", kparams.UnicodeString, []string{"pe.cert.subject contains 'Washington, Redmond, Microsoft Corporation'"}, nil},
	PeCertIssuer:      {PeCertIssuer, "PE certificate CA", kparams.UnicodeString, []string{"pe.cert.issuer contains 'Washington, Redmond, Microsoft Corporation'"}, nil},
	PeCertAfter:       {PeCertAfter, "PE certificate expiration date", kparams.Time, []string{"pe.cert.after contains '2024-02-01 00:05:42 +0000 UTC'"}, nil},
	PeCertBefore:      {PeCertBefore, "PE certificate enrollment date", kparams.Time, []string{"pe.cert.before contains '2024-02-01 00:05:42 +0000 UTC'"}, nil},
	PeIsModified:      {PeIsModified, "indicates if disk and in-memory PE headers differ", kparams.Bool, []string{"pe.is_modified"}, nil},
	PePsChildFileName: {PePsChildFileName, "original file name of the child process executable supplied at compile-time", kparams.UnicodeString, []string{"pe.ps.child.file.name = 'NOTEPAD.EXE'"}, &Deprecation{Since: "2.3.0", Fields: []Field{PsChildPeFilename}}},

	MemBaseAddress:    {MemBaseAddress, "region base address", kparams.Address, []string{"mem.address = '211d13f2000'"}, nil},
	MemRegionSize:     {MemRegionSize, "region size", kparams.Uint64, []string{"mem.size > 438272"}, nil},
	MemAllocType:      {MemAllocType, "region allocation or release type", kparams.Flags, []string{"mem.alloc = 'COMMIT'"}, nil},
	MemPageType:       {MemPageType, "page type of the allocated region", kparams.Enum, []string{"mem.type = 'PRIVATE'"}, nil},
	MemProtection:     {MemProtection, "allocated region protection type", kparams.Enum, []string{"mem.protection = 'READWRITE'"}, nil},
	MemProtectionMask: {MemProtectionMask, "allocated region protection in mask notation", kparams.Enum, []string{"mem.protection.mask = 'RWX'"}, nil},

	DNSName:    {DNSName, "dns query name", kparams.UnicodeString, []string{"dns.name = 'example.org'"}, nil},
	DNSRR:      {DNSRR, "dns resource record type", kparams.AnsiString, []string{"dns.rr = 'AA'"}, nil},
	DNSOptions: {DNSOptions, "dns query options", kparams.Flags64, []string{"dns.options in ('ADDRCONFIG', 'DUAL_ADDR')"}, nil},
	DNSRcode:   {DNSRR, "dns response status", kparams.AnsiString, []string{"dns.rcode = 'NXDOMAIN'"}, nil},
	DNSAnswers: {DNSAnswers, "dns response answers", kparams.Slice, []string{"dns.answers in ('o.lencr.edgesuite.net', 'a1887.dscq.akamai.net')"}, nil},
}

// Lookup finds the field literal in the map. For the nested fields, it checks the pattern matches
// the expected one and compares the paths. If all checks pass, the full segment field literal
// is returned.
func Lookup(name string) Field {
	if _, ok := fields[Field(name)]; ok {
		return Field(name)
	}
	groups := pathRegexp.FindStringSubmatch(name)
	if len(groups) != 4 {
		return None
	}

	field := groups[1]   // `ps.envs` is a field in ps.envs[PATH]
	key := groups[2]     // `PATH` is a key in ps.envs[PATH]
	segment := groups[3] // `entropy` is a segment in pe.sections[.text].entropy

	switch Field(field) {
	case PeSections:
		if segment == "" {
			return None
		}
		if Segment(segment).IsSection() {
			return Field(name)
		}
	case PsModules:
		if segment == "" {
			return None
		}
		if Segment(segment).IsModule() {
			return Field(name)
		}
	case PsAncestor:
		if segment == "" {
			return None
		}
		// the key is either the number
		// that represents the depth of
		// the ancestor process node or the
		// `root` keyword to designate the
		// root ancestor process node. Additionally,
		// we can also get the `any` keyword
		// that collects the fields of all
		// ancestor processes
		var keyRegexp = regexp.MustCompile(`^[1-9]+$|^root$|^any$`)
		if !keyRegexp.MatchString(key) {
			return None
		}
		if Segment(segment).IsProcess() {
			return Field(name)
		}
	case PeResources:
		if key != "" && segment == "" {
			return Field(name)
		}
	case PsEnvs, KevtArg:
		if key != "" {
			return Field(name)
		}
	case ThreadCallstack:
		if segment == "" {
			return None
		}
		// the key can be the stack frame
		// index with 0 being the bottom
		// userspace frame. u/k start/end
		// keys identify the start/end
		// user and kernel space frames.
		// Lastly, it is possible to specify
		// the name of the module from which
		// the call was originated
		var keyRegexp = regexp.MustCompile(`^[0-9]+$|^uend$|^ustart$|^kend$|^kstart$|^[a-zA-Z0-9]+\.dll$`)
		if !keyRegexp.MatchString(key) {
			return None
		}
		if Segment(segment).IsCallstack() {
			return Field(name)
		}
	}
	return None
}
