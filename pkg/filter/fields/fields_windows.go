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
var pathRegexp = regexp.MustCompile(`(pe.sections|pe.resources|ps.envs|ps.modules|ps.ancestor|kevt.arg)\[(.+\s*)].?(.*)`)

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
	// ThreadPID is the process identifier where the thread is created
	ThreadPID Field = "thread.pid"
	// ThreadAccessMask represents the thread access rights field
	ThreadAccessMask Field = "thread.access.mask"
	// ThreadAccessMaskNames represents the thread access rights list field
	ThreadAccessMaskNames Field = "thread.access.mask.names"
	// ThreadAccessStatus represents the thread access status field
	ThreadAccessStatus Field = "thread.access.status"

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
func (f Field) IsPeField() bool       { return strings.HasPrefix(string(f), "pe.") }

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
)

func (f Field) IsEnvsMap() bool        { return strings.HasPrefix(f.String(), "ps.envs[") }
func (f Field) IsModsMap() bool        { return strings.HasPrefix(f.String(), "ps.modules[") }
func (f Field) IsAncestorMap() bool    { return strings.HasPrefix(f.String(), "ps.ancestor[") }
func (f Field) IsPeSectionsMap() bool  { return strings.HasPrefix(f.String(), "pe.sections[") }
func (f Field) IsPeResourcesMap() bool { return strings.HasPrefix(f.String(), "pe.resources[") }
func (f Field) IsKevtArgMap() bool     { return strings.HasPrefix(f.String(), "kevt.arg[") }

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

	PsPid:               {PsPid, "process identifier", kparams.PID, []string{"ps.pid = 1024"}, nil},
	PsPpid:              {PsPpid, "parent process identifier", kparams.PID, []string{"ps.ppid = 45"}, nil},
	PsName:              {PsName, "process image name including the file extension", kparams.UnicodeString, []string{"ps.name contains 'firefox'"}, nil},
	PsComm:              {PsComm, "process command line", kparams.UnicodeString, []string{"ps.comm contains 'java'"}, &Deprecation{Since: "1.10.0", Field: PsCmdline}},
	PsCmdline:           {PsCmdline, "process command line", kparams.UnicodeString, []string{"ps.cmdline contains 'java'"}, nil},
	PsExe:               {PsExe, "full name of the process' executable", kparams.UnicodeString, []string{"ps.exe = 'C:\\Windows\\system32\\cmd.exe'"}, nil},
	PsArgs:              {PsArgs, "process command line arguments", kparams.Slice, []string{"ps.args in ('/cdir', '/-C')"}, nil},
	PsCwd:               {PsCwd, "process current working directory", kparams.UnicodeString, []string{"ps.cwd = 'C:\\Users\\Default'"}, nil},
	PsSID:               {PsSID, "security identifier under which this process is run", kparams.UnicodeString, []string{"ps.sid contains 'SYSTEM'"}, nil},
	PsSessionID:         {PsSessionID, "unique identifier for the current session", kparams.Int16, []string{"ps.sessionid = 1"}, nil},
	PsDomain:            {PsDomain, "process domain", kparams.UnicodeString, []string{"ps.domain contains 'SERVICE'"}, nil},
	PsUsername:          {PsUsername, "process username", kparams.UnicodeString, []string{"ps.username contains 'system'"}, nil},
	PsEnvs:              {PsEnvs, "process environment variables", kparams.Slice, []string{"ps.envs in ('MOZ_CRASHREPORTER_DATA_DIRECTORY')"}, nil},
	PsHandles:           {PsHandles, "allocated process handle names", kparams.Slice, []string{"ps.handles in ('\\BaseNamedObjects\\__ComCatalogCache__')"}, nil},
	PsHandleTypes:       {PsHandleTypes, "allocated process handle types", kparams.Slice, []string{"ps.handle.types in ('Key', 'Mutant', 'Section')"}, nil},
	PsDTB:               {PsDTB, "process directory table base address", kparams.HexInt64, []string{"ps.dtb = '7ffe0000'"}, nil},
	PsModules:           {PsModules, "modules loaded by the process", kparams.Slice, []string{"ps.modules in ('crypt32.dll', 'xul.dll')"}, nil},
	PsParentName:        {PsParentName, "parent process image name including the file extension", kparams.UnicodeString, []string{"ps.parent.name contains 'cmd.exe'"}, nil},
	PsParentPid:         {PsParentPid, "parent process id", kparams.Uint32, []string{"ps.parent.pid = 4"}, nil},
	PsParentComm:        {PsParentComm, "parent process command line", kparams.UnicodeString, []string{"ps.parent.comm contains 'java'"}, &Deprecation{Since: "1.10.0", Field: PsParentCmdline}},
	PsParentCmdline:     {PsParentCmdline, "parent process command line", kparams.UnicodeString, []string{"ps.parent.cmdline contains 'java'"}, nil},
	PsParentExe:         {PsParentExe, "full name of the parent process' executable", kparams.UnicodeString, []string{"ps.parent.exe = 'C:\\Windows\\system32\\explorer.exe'"}, nil},
	PsParentArgs:        {PsParentArgs, "parent process command line arguments", kparams.Slice, []string{"ps.parent.args in ('/cdir', '/-C')"}, nil},
	PsParentCwd:         {PsParentCwd, "parent process current working directory", kparams.UnicodeString, []string{"ps.parent.cwd = 'C:\\Temp'"}, nil},
	PsParentSID:         {PsParentSID, "security identifier under which the parent process is run", kparams.UnicodeString, []string{"ps.parent.sid contains 'SYSTEM'"}, nil},
	PsParentDomain:      {PsParentDomain, "parent process domain", kparams.UnicodeString, []string{"ps.parent.domain contains 'SERVICE'"}, nil},
	PsParentUsername:    {PsParentUsername, "parent process username", kparams.UnicodeString, []string{"ps.parent.username contains 'system'"}, nil},
	PsParentSessionID:   {PsParentSessionID, "unique identifier for the current session of parent process", kparams.Int16, []string{"ps.parent.sessionid = 1"}, nil},
	PsParentEnvs:        {PsParentEnvs, "parent process environment variables", kparams.Slice, []string{"ps.parent.envs in ('MOZ_CRASHREPORTER_DATA_DIRECTORY')"}, nil},
	PsParentHandles:     {PsParentHandles, "allocated parent process handle names", kparams.Slice, []string{"ps.parent.handles in ('\\BaseNamedObjects\\__ComCatalogCache__')"}, nil},
	PsParentHandleTypes: {PsParentHandleTypes, "allocated parent process handle types", kparams.Slice, []string{"ps.parent.handle.types in ('File', 'SymbolicLink')"}, nil},
	PsParentDTB:         {PsParentDTB, "parent process directory table base address", kparams.HexInt64, []string{"ps.parent.dtb = '7ffe0000'"}, nil},
	PsAccessMask:        {PsAccessMask, "process desired access rights", kparams.AnsiString, []string{"ps.access.mask = '0x1400'"}, nil},
	PsAccessMaskNames:   {PsAccessMaskNames, "process desired access rights as a string list", kparams.Slice, []string{"ps.access.mask.names in ('SUSPEND_RESUME')"}, nil},
	PsAccessStatus:      {PsAccessStatus, "process access status", kparams.UnicodeString, []string{"ps.access.status = 'access is denied.'"}, nil},
	PsSiblingPid:        {PsSiblingPid, "created or terminated process identifier", kparams.PID, []string{"ps.sibling.pid = 320"}, &Deprecation{Since: "1.10.0", Field: PsChildPid}},
	PsChildPid:          {PsChildPid, "created or terminated process identifier", kparams.PID, []string{"ps.child.pid = 320"}, nil},
	PsSiblingName:       {PsSiblingName, "created or terminated process name", kparams.UnicodeString, []string{"ps.sibling.name = 'notepad.exe'"}, &Deprecation{Since: "1.10.0", Field: PsChildName}},
	PsChildName:         {PsChildName, "created or terminated process name", kparams.UnicodeString, []string{"ps.child.name = 'notepad.exe'"}, nil},
	PsSiblingComm:       {PsSiblingComm, "created or terminated process command line", kparams.UnicodeString, []string{"ps.sibling.comm contains '\\k \\v'"}, &Deprecation{Since: "1.10.0", Field: PsChildCmdline}},
	PsChildCmdline:      {PsChildCmdline, "created or terminated process command line", kparams.UnicodeString, []string{"ps.child.cmdline contains '\\k \\v'"}, nil},
	PsSiblingArgs:       {PsSiblingArgs, "created process command line arguments", kparams.Slice, []string{"ps.sibling.args in ('/cdir', '/-C')"}, &Deprecation{Since: "1.10.0", Field: PsChildArgs}},
	PsChildArgs:         {PsChildArgs, "created process command line arguments", kparams.Slice, []string{"ps.child.args in ('/cdir', '/-C')"}, nil},
	PsSiblingExe:        {PsSiblingExe, "created, terminated, or opened process id", kparams.UnicodeString, []string{"ps.sibling.exe contains '\\Windows\\cmd.exe'"}, &Deprecation{Since: "1.10.0", Field: PsChildExe}},
	PsChildExe:          {PsChildExe, "created, terminated, or opened process id", kparams.UnicodeString, []string{"ps.child.exe contains '\\Windows\\cmd.exe'"}, nil},
	PsSiblingSID:        {PsSiblingSID, "created or terminated process security identifier", kparams.UnicodeString, []string{"ps.sibling.sid contains 'SERVICE'"}, &Deprecation{Since: "1.10.0", Field: PsChildSID}},
	PsChildSID:          {PsChildSID, "created or terminated process security identifier", kparams.UnicodeString, []string{"ps.child.sid contains 'SERVICE'"}, nil},
	PsSiblingSessionID:  {PsSiblingSessionID, "created or terminated process session identifier", kparams.Int16, []string{"ps.sibling.sessionid == 1"}, &Deprecation{Since: "1.10.0", Field: PsChildSessionID}},
	PsChildSessionID:    {PsChildSessionID, "created or terminated process session identifier", kparams.Int16, []string{"ps.child.sessionid == 1"}, nil},
	PsSiblingDomain:     {PsSiblingDomain, "created or terminated process domain", kparams.UnicodeString, []string{"ps.sibling.domain contains 'SERVICE'"}, &Deprecation{Since: "1.10.0", Field: PsChildDomain}},
	PsChildDomain:       {PsChildDomain, "created or terminated process domain", kparams.UnicodeString, []string{"ps.child.domain contains 'SERVICE'"}, nil},
	PsSiblingUsername:   {PsSiblingUsername, "created or terminated process username", kparams.UnicodeString, []string{"ps.sibling.username contains 'system'"}, &Deprecation{Since: "1.10.0", Field: PsChildUsername}},
	PsChildUsername:     {PsChildUsername, "created or terminated process username", kparams.UnicodeString, []string{"ps.child.username contains 'system'"}, nil},
	PsUUID:              {PsUUID, "unique process identifier", kparams.Uint64, []string{"ps.uuid > 6000054355"}, nil},
	PsParentUUID:        {PsParentUUID, "unique parent process identifier", kparams.Uint64, []string{"ps.parent.uuid > 6000054355"}, nil},
	PsChildUUID:         {PsChildUUID, "unique child process identifier", kparams.Uint64, []string{"ps.child.uuid > 6000054355"}, nil},

	ThreadBasePrio:        {ThreadBasePrio, "scheduler priority of the thread", kparams.Int8, []string{"thread.prio = 5"}, nil},
	ThreadIOPrio:          {ThreadIOPrio, "I/O priority hint for scheduling I/O operations", kparams.Int8, []string{"thread.io.prio = 4"}, nil},
	ThreadPagePrio:        {ThreadPagePrio, "memory page priority hint for memory pages accessed by the thread", kparams.Int8, []string{"thread.page.prio = 12"}, nil},
	ThreadKstackBase:      {ThreadKstackBase, "base address of the thread's kernel space stack", kparams.HexInt64, []string{"thread.kstack.base = 'a65d800000'"}, nil},
	ThreadKstackLimit:     {ThreadKstackLimit, "limit of the thread's kernel space stack", kparams.HexInt64, []string{"thread.kstack.limit = 'a85d800000'"}, nil},
	ThreadUstackBase:      {ThreadUstackBase, "base address of the thread's user space stack", kparams.HexInt64, []string{"thread.ustack.base = '7ffe0000'"}, nil},
	ThreadUstackLimit:     {ThreadUstackLimit, "limit of the thread's user space stack", kparams.HexInt64, []string{"thread.ustack.limit = '8ffe0000'"}, nil},
	ThreadEntrypoint:      {ThreadEntrypoint, "starting address of the function to be executed by the thread", kparams.HexInt64, []string{"thread.entrypoint = '7efe0000'"}, nil},
	ThreadPID:             {ThreadPID, "the process identifier where the thread is created", kparams.Uint32, []string{"kevt.pid != thread.pid"}, nil},
	ThreadAccessMask:      {ThreadAccessMask, "thread desired access rights", kparams.AnsiString, []string{"thread.access.mask = '0x1fffff'"}, nil},
	ThreadAccessMaskNames: {ThreadAccessMaskNames, "thread desired access rights as a string list", kparams.Slice, []string{"thread.access.mask.names in ('IMPERSONATE')"}, nil},
	ThreadAccessStatus:    {ThreadAccessStatus, "thread access status", kparams.UnicodeString, []string{"thread.access.status = 'success'"}, nil},

	ImageName:           {ImageName, "full image name", kparams.UnicodeString, []string{"image.name contains 'advapi32.dll'"}, nil},
	ImageBase:           {ImageBase, "the base address of process in which the image is loaded", kparams.HexInt64, []string{"image.base.address = 'a65d800000'"}, nil},
	ImageChecksum:       {ImageChecksum, "image checksum", kparams.Uint32, []string{"image.checksum = 746424"}, nil},
	ImageSize:           {ImageSize, "image size", kparams.Uint32, []string{"image.size > 1024"}, nil},
	ImageDefaultAddress: {ImageDefaultAddress, "default image address", kparams.HexInt64, []string{"image.default.address = '7efe0000'"}, nil},
	ImagePID:            {ImagePID, "target process identifier", kparams.Uint32, []string{"image.pid = 80"}, nil},

	FileObject:     {FileObject, "file object address", kparams.Uint64, []string{"file.object = 18446738026482168384"}, nil},
	FileName:       {FileName, "full file name", kparams.UnicodeString, []string{"file.name contains 'mimikatz'"}, nil},
	FileOperation:  {FileOperation, "file operation", kparams.AnsiString, []string{"file.operation = 'open'"}, nil},
	FileShareMask:  {FileShareMask, "file share mask", kparams.AnsiString, []string{"file.share.mask = 'rw-'"}, nil},
	FileIOSize:     {FileIOSize, "file I/O size", kparams.Uint32, []string{"file.io.size > 512"}, nil},
	FileOffset:     {FileOffset, "file offset", kparams.Uint64, []string{"file.offset = 1024"}, nil},
	FileType:       {FileType, "file type", kparams.AnsiString, []string{"file.type = 'directory'"}, nil},
	FileExtension:  {FileExtension, "file extension", kparams.AnsiString, []string{"file.extension = '.dll'"}, nil},
	FileAttributes: {FileAttributes, "file attributes", kparams.Slice, []string{"file.attributes in ('archive', 'hidden')"}, nil},
	FileStatus:     {FileStatus, "file operation status message", kparams.UnicodeString, []string{"file.status != 'success'"}, nil},

	RegistryKeyName:   {RegistryKeyName, "fully qualified key name", kparams.UnicodeString, []string{"registry.key.name contains 'HKEY_LOCAL_MACHINE'"}, nil},
	RegistryKeyHandle: {RegistryKeyHandle, "registry key object address", kparams.HexInt64, []string{"registry.key.handle = 'FFFFB905D60C2268'"}, nil},
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
	HandleObject: {HandleObject, "handle object address", kparams.HexInt64, []string{"handle.object = 'FFFFB905DBF61988'"}, nil},
	HandleName:   {HandleName, "handle name", kparams.UnicodeString, []string{"handle.name = '\\Device\\NamedPipe\\chrome.12644.28.105826381'"}, nil},
	HandleType:   {HandleType, "handle type", kparams.AnsiString, []string{"handle.type = 'Mutant'"}, nil},

	PeNumSections:    {PeNumSections, "number of sections", kparams.Uint16, []string{"pe.nsections < 5"}, nil},
	PeNumSymbols:     {PeNumSymbols, "number of entries in the symbol table", kparams.Uint32, []string{"pe.nsymbols > 230"}, nil},
	PeBaseAddress:    {PeBaseAddress, "image base address", kparams.HexInt64, []string{"pe.address.base = '140000000'"}, nil},
	PeEntrypoint:     {PeEntrypoint, "address of the entrypoint function", kparams.HexInt64, []string{"pe.address.entrypoint = '20110'"}, nil},
	PeSections:       {PeSections, "PE sections", kparams.Object, []string{"pe.sections[.text].entropy > 6.2"}, nil},
	PeSymbols:        {PeSymbols, "imported symbols", kparams.Slice, []string{"pe.symbols in ('GetTextFaceW', 'GetProcessHeap')"}, nil},
	PeImports:        {PeImports, "imported dynamic linked libraries", kparams.Slice, []string{"pe.imports in ('msvcrt.dll', 'GDI32.dll'"}, nil},
	PeResources:      {PeResources, "version and other resources", kparams.Map, []string{"pe.resources[FileDescription] = 'Notepad'"}, nil},
	PeCompany:        {PeCompany, "internal company name of the file provided at compile-time", kparams.UnicodeString, []string{"pe.company = 'Microsoft Corporation'"}, nil},
	PeCopyright:      {PeCopyright, "copyright notice for the file emitted at compile-time", kparams.UnicodeString, []string{"pe.copyright = '© Microsoft Corporation'"}, nil},
	PeDescription:    {PeDescription, "internal description of the file provided at compile-time", kparams.UnicodeString, []string{"pe.description = 'Notepad'"}, nil},
	PeFileName:       {PeFileName, "original file name supplied at compile-time", kparams.UnicodeString, []string{"pe.file.name = 'NOTEPAD.EXE'"}, nil},
	PeFileVersion:    {PeFileVersion, "file version supplied at compile-time", kparams.UnicodeString, []string{"pe.file.version = '10.0.18362.693 (WinBuild.160101.0800)'"}, nil},
	PeProduct:        {PeProduct, "internal product name of the file provided at compile-time", kparams.UnicodeString, []string{"pe.product = 'Microsoft® Windows® Operating System'"}, nil},
	PeProductVersion: {PeProductVersion, "internal product version of the file provided at compile-time", kparams.UnicodeString, []string{"pe.product.version = '10.0.18362.693'"}, nil},
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
		switch Segment(segment) {
		case SectionEntropy:
			return Field(name)
		case SectionMD5Hash:
			return Field(name)
		case SectionSize:
			return Field(name)
		}
	case PsModules:
		if segment == "" {
			return None
		}
		switch Segment(segment) {
		case ModuleSize:
			return Field(name)
		case ModuleChecksum:
			return Field(name)
		case ModuleDefaultAddress:
			return Field(name)
		case ModuleBaseAddress:
			return Field(name)
		case ModuleLocation:
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
		var keyRegexp = regexp.MustCompile(`[1-9]+|root|any`)
		if !keyRegexp.MatchString(key) {
			return None
		}
		switch Segment(segment) {
		case ProcessName:
			return Field(name)
		case ProcessID:
			return Field(name)
		case ProcessArgs:
			return Field(name)
		case ProcessCmdline:
			return Field(name)
		case ProcessCwd:
			return Field(name)
		case ProcessExe:
			return Field(name)
		case ProcessSID:
			return Field(name)
		case ProcessSessionID:
			return Field(name)
		}
	case PeResources, PsEnvs, KevtArg:
		if key != "" && segment == "" {
			return Field(name)
		}
	}
	return None
}
