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
	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"regexp"
	"sort"
)

// pathRegexp splits the provided path into different components. The first capture
// contains the indexed field name. Next is the indexed key and, finally the segment.
var pathRegexp = regexp.MustCompile(`(pe.sections|pe.resources|ps.envs|ps.modules|ps.parent)\[(.+\s*)].?(.*)`)

// Field represents the type alias for the field
type Field string

const (
	// PsPid represents the process id field
	PsPid Field = "ps.pid"
	// PsPpid represents the parent process id field
	PsPpid Field = "ps.ppid"
	// PsName represents the process name field
	PsName Field = "ps.name"
	// PsComm represents the process command line field
	PsComm Field = "ps.comm"
	// PsExe represents the process image path field
	PsExe Field = "ps.exe"
	// PsArgs represents the process command line arguments
	PsArgs Field = "ps.args"
	// PsCwd represents the process current working directory
	PsCwd Field = "ps.cwd"
	// PsSID represents the process security identifier
	PsSID Field = "ps.sid"
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
	// PsParentName represents the parent process name field
	PsParentName Field = "ps.parent.name"
	// PsParentComm represents the parent process command line field
	PsParentComm Field = "ps.parent.comm"
	// PsParentExe represents the parent process image path field
	PsParentExe Field = "ps.parent.exe"
	// PsParentArgs represents the parent process command line arguments field
	PsParentArgs Field = "ps.parent.args"
	// PsParentCwd represents the parent process current working directory field
	PsParentCwd Field = "ps.parent.cwd"
	// PsParentSID represents the parent process security identifier field
	PsParentSID Field = "ps.parent.sid"
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
	// PsParent represents the parent process sequence field
	PsParent Field = "ps.parent"

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
	// PsComm represents the process command line
	ProcessComm Segment = "comm"
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

const (
	// PsEnvsSequence denotes the beginning of the process environment variables sequence
	PsEnvsSequence = "ps.envs["
	// PsModsSequence denotes the beginning of  the process modules sequence
	PsModsSequence = "ps.modules["
	// PsParentSequence denotes the start of the parent processes sequence
	PsParentSequence = "ps.parent["
	// PeSectionsSequence denotes the start of the PE sections sequence
	PeSectionsSequence = "pe.sections["
	// PeResourcesSequence denotes the beginning opf the he PE resources sequence
	PeResourcesSequence = "pe.resources["
)

// FieldInfo is the field metadata descriptor.
type FieldInfo struct {
	Field    Field
	Desc     string
	Type     kparams.Type
	Examples []string
}

var fields = map[Field]FieldInfo{
	KevtSeq:         {KevtSeq, "event sequence number", kparams.Uint64, []string{"kevt.seq > 666"}},
	KevtPID:         {KevtPID, "process identifier generating the kernel event", kparams.Uint32, []string{"kevt.pid = 6"}},
	KevtTID:         {KevtTID, "thread identifier generating the kernel event", kparams.Uint32, []string{"kevt.tid = 1024"}},
	KevtCPU:         {KevtCPU, "logical processor core where the event was generated", kparams.Uint8, []string{"kevt.cpu = 2"}},
	KevtName:        {KevtName, "symbolical kernel event name", kparams.AnsiString, []string{"kevt.name = 'CreateThread'"}},
	KevtCategory:    {KevtCategory, "event category", kparams.AnsiString, []string{"kevt.category = 'registry'"}},
	KevtDesc:        {KevtDesc, "event description", kparams.AnsiString, []string{"kevt.desc contains 'Creates a new process'"}},
	KevtHost:        {KevtHost, "host name on which the event was produced", kparams.UnicodeString, []string{"kevt.host contains 'kitty'"}},
	KevtTime:        {KevtTime, "event timestamp as a time string", kparams.Time, []string{"kevt.time = '17:05:32'"}},
	KevtTimeHour:    {KevtTimeHour, "hour within the day on which the event occurred", kparams.Time, []string{"kevt.time.h = 23"}},
	KevtTimeMin:     {KevtTimeMin, "minute offset within the hour on which the event occurred", kparams.Time, []string{"kevt.time.m = 54"}},
	KevtTimeSec:     {KevtTimeSec, "second offset within the minute  on which the event occurred", kparams.Time, []string{"kevt.time.s = 0"}},
	KevtTimeNs:      {KevtTimeNs, "nanoseconds specified by event timestamp", kparams.Int64, []string{"kevt.time.ns > 1591191629102337000"}},
	KevtDate:        {KevtDate, "event timestamp as a date string", kparams.Time, []string{"kevt.date = '2018-03-03'"}},
	KevtDateDay:     {KevtDateDay, "day of the month on which the event occurred", kparams.Time, []string{"kevt.date.d = 12"}},
	KevtDateMonth:   {KevtDateMonth, "month of the year on which the event occurred", kparams.Time, []string{"kevt.date.m = 11"}},
	KevtDateYear:    {KevtDateYear, "year on which the event occurred", kparams.Uint32, []string{"kevt.date.y = 2020"}},
	KevtDateTz:      {KevtDateTz, "time zone associated with the event timestamp", kparams.AnsiString, []string{"kevt.date.tz = 'UTC'"}},
	KevtDateWeek:    {KevtDateWeek, "week number within the year on which the event occurred", kparams.Uint8, []string{"kevt.date.week = 2"}},
	KevtDateWeekday: {KevtDateWeekday, "week day on which the event occurred", kparams.AnsiString, []string{"kevt.date.weekday = 'Monday'"}},
	KevtNparams:     {KevtNparams, "number of parameters", kparams.Int8, []string{"kevt.nparams > 2"}},

	PsPid:               {PsPid, "process identifier", kparams.PID, []string{"ps.pid = 1024"}},
	PsPpid:              {PsPpid, "parent process identifier", kparams.PID, []string{"ps.ppid = 45"}},
	PsName:              {PsName, "process image name including the file extension", kparams.UnicodeString, []string{"ps.name contains 'firefox'"}},
	PsComm:              {PsComm, "process command line", kparams.UnicodeString, []string{"ps.comm contains 'java'"}},
	PsExe:               {PsExe, "full name of the process' executable", kparams.UnicodeString, []string{"ps.exe = 'C:\\Windows\\system32\\cmd.exe'"}},
	PsArgs:              {PsArgs, "process command line arguments", kparams.Slice, []string{"ps.args in ('/cdir', '/-C')"}},
	PsCwd:               {PsCwd, "process current working directory", kparams.UnicodeString, []string{"ps.cwd = 'C:\\Users\\Default'"}},
	PsSID:               {PsSID, "security identifier under which this process is run", kparams.UnicodeString, []string{"ps.sid contains 'SYSTEM'"}},
	PsSessionID:         {PsSessionID, "unique identifier for the current session", kparams.Int16, []string{"ps.sessionid = 1"}},
	PsEnvs:              {PsEnvs, "process environment variables", kparams.Slice, []string{"ps.envs in ('MOZ_CRASHREPORTER_DATA_DIRECTORY')"}},
	PsHandles:           {PsHandles, "allocated process handle names", kparams.Slice, []string{"ps.handles in ('\\BaseNamedObjects\\__ComCatalogCache__')"}},
	PsHandleTypes:       {PsHandleTypes, "allocated process handle types", kparams.Slice, []string{"ps.handle.types in ('Key', 'Mutant', 'Section')"}},
	PsDTB:               {PsDTB, "process directory table base address", kparams.HexInt64, []string{"ps.dtb = '7ffe0000'"}},
	PsModules:           {PsModules, "modules loaded by the process", kparams.Slice, []string{"ps.modules in ('crypt32.dll', 'xul.dll')"}},
	PsParentName:        {PsParentName, "parent process image name including the file extension", kparams.UnicodeString, []string{"ps.parent.name contains 'cmd.exe'"}},
	PsParentComm:        {PsParentComm, "parent process command line", kparams.UnicodeString, []string{"parent.ps.comm contains 'java'"}},
	PsParentExe:         {PsParentExe, "full name of the parent process' executable", kparams.UnicodeString, []string{"ps.parent.exe = 'C:\\Windows\\system32\\explorer.exe'"}},
	PsParentArgs:        {PsParentArgs, "parent process command line arguments", kparams.Slice, []string{"ps.parent.args in ('/cdir', '/-C')"}},
	PsParentCwd:         {PsParentCwd, "parent process current working directory", kparams.UnicodeString, []string{"ps.parent.cwd = 'C:\\Temp'"}},
	PsParentSID:         {PsParentSID, "security identifier under which the parent process is run", kparams.UnicodeString, []string{"ps.parent.sid contains 'SYSTEM'"}},
	PsParentSessionID:   {PsParentSessionID, "unique identifier for the current session of parent process", kparams.Int16, []string{"ps.parent.sessionid = 1"}},
	PsParentEnvs:        {PsParentEnvs, "parent process environment variables", kparams.Slice, []string{"ps.parent.envs in ('MOZ_CRASHREPORTER_DATA_DIRECTORY')"}},
	PsParentHandles:     {PsParentHandles, "allocated parent process handle names", kparams.Slice, []string{"ps.parent.handles in ('\\BaseNamedObjects\\__ComCatalogCache__')"}},
	PsParentHandleTypes: {PsParentHandleTypes, "allocated parent process handle types", kparams.Slice, []string{"ps.parent.handle.types in ('File', 'SymbolicLink')"}},
	PsParentDTB:         {PsParentDTB, "parent process directory table base address", kparams.HexInt64, []string{"ps.parent.dtb = '7ffe0000'"}},

	ThreadBasePrio:    {ThreadBasePrio, "scheduler priority of the thread", kparams.Int8, []string{"thread.prio = 5"}},
	ThreadIOPrio:      {ThreadIOPrio, "I/O priority hint for scheduling I/O operations", kparams.Int8, []string{"thread.io.prio = 4"}},
	ThreadPagePrio:    {ThreadPagePrio, "memory page priority hint for memory pages accessed by the thread", kparams.Int8, []string{"thread.page.prio = 12"}},
	ThreadKstackBase:  {ThreadKstackBase, "base address of the thread's kernel space stack", kparams.HexInt64, []string{"thread.kstack.base = 'a65d800000'"}},
	ThreadKstackLimit: {ThreadKstackLimit, "limit of the thread's kernel space stack", kparams.HexInt64, []string{"thread.kstack.limit = 'a85d800000'"}},
	ThreadUstackBase:  {ThreadUstackBase, "base address of the thread's user space stack", kparams.HexInt64, []string{"thread.ustack.base = '7ffe0000'"}},
	ThreadUstackLimit: {ThreadUstackLimit, "limit of the thread's user space stack", kparams.HexInt64, []string{"thread.ustack.limit = '8ffe0000'"}},
	ThreadEntrypoint:  {ThreadEntrypoint, "starting address of the function to be executed by the thread", kparams.HexInt64, []string{"thread.entrypoint = '7efe0000'"}},
	ThreadPID:         {ThreadPID, "the process identifier where the thread is created", kparams.Uint32, []string{"kevt.pid != thread.pid"}},

	ImageName:           {ImageName, "full image name", kparams.UnicodeString, []string{"image.name contains 'advapi32.dll'"}},
	ImageBase:           {ImageBase, "the base address of process in which the image is loaded", kparams.HexInt64, []string{"image.base.address = 'a65d800000'"}},
	ImageChecksum:       {ImageChecksum, "image checksum", kparams.Uint32, []string{"image.checksum = 746424"}},
	ImageSize:           {ImageSize, "image size", kparams.Uint32, []string{"image.size > 1024"}},
	ImageDefaultAddress: {ImageDefaultAddress, "default image address", kparams.HexInt64, []string{"image.default.address = '7efe0000'"}},
	ImagePID:            {ImagePID, "target process identifier", kparams.Uint32, []string{"image.pid = 80"}},

	FileObject:    {FileObject, "file object address", kparams.Uint64, []string{"file.object = 18446738026482168384"}},
	FileName:      {FileName, "full file name", kparams.UnicodeString, []string{"file.name contains 'mimikatz'"}},
	FileOperation: {FileOperation, "file operation", kparams.AnsiString, []string{"file.operation = 'open'"}},
	FileShareMask: {FileShareMask, "file share mask", kparams.AnsiString, []string{"file.share.mask = 'rw-'"}},
	FileIOSize:    {FileIOSize, "file I/O size", kparams.Uint32, []string{"file.io.size > 512"}},
	FileOffset:    {FileOffset, "file offset", kparams.Uint64, []string{"file.offset = 1024"}},
	FileType:      {FileType, "file type", kparams.AnsiString, []string{"file.type = 'directory'"}},
	FileExtension: {FileExtension, "file extension", kparams.AnsiString, []string{"file.extension = '.dll'"}},

	RegistryKeyName:   {RegistryKeyName, "fully qualified key name", kparams.UnicodeString, []string{"registry.key.name contains 'HKEY_LOCAL_MACHINE'"}},
	RegistryKeyHandle: {RegistryKeyHandle, "registry key object address", kparams.HexInt64, []string{"registry.key.handle = 'FFFFB905D60C2268'"}},
	RegistryValue:     {RegistryValue, "registry value content", kparams.UnicodeString, []string{"registry.value = '%SystemRoot%\\system32'"}},
	RegistryValueType: {RegistryValueType, "type of registry value", kparams.UnicodeString, []string{"registry.value.type = 'REG_SZ'"}},
	RegistryStatus:    {RegistryStatus, "status of registry operation", kparams.UnicodeString, []string{"registry.status != 'success'"}},

	NetDIP:        {NetDIP, "destination IP address", kparams.IP, []string{"net.dip = 172.17.0.3"}},
	NetSIP:        {NetSIP, "source IP address", kparams.IP, []string{"net.sip = 127.0.0.1"}},
	NetDport:      {NetDport, "destination port", kparams.Uint16, []string{"net.dport in (80, 443, 8080)"}},
	NetSport:      {NetSport, "source port", kparams.Uint16, []string{"net.sport != 3306"}},
	NetDportName:  {NetDportName, "destination port name", kparams.AnsiString, []string{"net.dport.name = 'dns'"}},
	NetSportName:  {NetSportName, "source port name", kparams.AnsiString, []string{"net.sport.name = 'http'"}},
	NetL4Proto:    {NetL4Proto, "layer 4 protocol name", kparams.AnsiString, []string{"net.l4.proto = 'TCP"}},
	NetPacketSize: {NetPacketSize, "packet size", kparams.Uint32, []string{"net.size > 512"}},
	NetSIPNames:   {NetSIPNames, "source IP names", kparams.Slice, []string{"net.sip.names in ('github.com.')"}},
	NetDIPNames:   {NetDIPNames, "destination IP names", kparams.Slice, []string{"net.dip.names in ('github.com.')"}},

	HandleID:     {HandleID, "handle identifier", kparams.Uint16, []string{"handle.id = 24"}},
	HandleObject: {HandleObject, "handle object address", kparams.HexInt64, []string{"handle.object = 'FFFFB905DBF61988'"}},
	HandleName:   {HandleName, "handle name", kparams.UnicodeString, []string{"handle.name = '\\Device\\NamedPipe\\chrome.12644.28.105826381'"}},
	HandleType:   {HandleType, "handle type", kparams.AnsiString, []string{"handle.type = 'Mutant'"}},

	PeNumSections: {PeNumSections, "number of sections", kparams.Uint16, []string{"pe.nsections < 5"}},
	PeNumSymbols:  {PeNumSymbols, "number of entries in the symbol table", kparams.Uint32, []string{"pe.nsymbols > 230"}},
	PeBaseAddress: {PeBaseAddress, "image base address", kparams.HexInt64, []string{"pe.address.base = '140000000'"}},
	PeEntrypoint:  {PeEntrypoint, "address of the entrypoint function", kparams.HexInt64, []string{"pe.address.entrypoint = '20110'"}},
	PeSections:    {PeSections, "PE sections", kparams.Object, []string{"pe.sections[.text].entropy > 6.2"}},
	PeSymbols:     {PeSymbols, "imported symbols", kparams.Slice, []string{"pe.symbols in ('GetTextFaceW', 'GetProcessHeap')"}},
	PeImports:     {PeImports, "imported dynamic linked libraries", kparams.Slice, []string{"pe.imports in ('msvcrt.dll', 'GDI32.dll'"}},
	PeResources:   {PeResources, "version and other resources", kparams.Map, []string{"pe.resources[FileDescription] = 'Notepad'"}},
}

// Get returns a slice of field information.
func Get() []FieldInfo {
	fi := make([]FieldInfo, 0, len(fields))
	for _, field := range fields {
		fi = append(fi, field)
	}
	sort.Slice(fi, func(i, j int) bool { return fi[i].Field < fi[j].Field })
	return fi
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

	field := groups[1]
	key := groups[2]
	segment := groups[3]

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
	case PsParent:
		if segment == "" {
			return None
		}
		// the key is either the number
		// that represents the depth of
		// the parent process node or the
		// `root` keyword to designate the
		// root process node. Additionally,
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
		case ProcessComm:
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
	case PeResources:
		if segment == "" {
			return Field(name)
		}
	case PsEnvs:
		if segment == "" {
			return Field(name)
		}
	}
	return None
}
