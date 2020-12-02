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

var subfieldRegexp = regexp.MustCompile(`(pe.sections|pe.resources|ps.envs|ps.modules)\[.+\s*].?(.*)`)

// Field represents the type alias for the field
type Field string

const (
	PsPid         Field = "ps.pid"
	PsPpid        Field = "ps.ppid"
	PsName        Field = "ps.name"
	PsComm        Field = "ps.comm"
	PsExe         Field = "ps.exe"
	PsArgs        Field = "ps.args"
	PsCwd         Field = "ps.cwd"
	PsSID         Field = "ps.sid"
	PsSessionID   Field = "ps.sessionid"
	PsEnvs        Field = "ps.envs"
	PsHandles     Field = "ps.handles"
	PsHandleTypes Field = "ps.handle.types"
	PsDTB         Field = "ps.dtb"
	PsModules     Field = "ps.modules"

	ThreadBasePrio    Field = "thread.prio"
	ThreadIOPrio      Field = "thread.io.prio"
	ThreadPagePrio    Field = "thread.page.prio"
	ThreadKstackBase  Field = "thread.kstack.base"
	ThreadKstackLimit Field = "thread.kstack.limit"
	ThreadUstackBase  Field = "thread.ustack.base"
	ThreadUstackLimit Field = "thread.ustack.limit"
	ThreadEntrypoint  Field = "thread.entrypoint"

	PeNumSections Field = "pe.nsections"
	PeSections    Field = "pe.sections"
	PeNumSymbols  Field = "pe.nsymbols"
	PeSymbols     Field = "pe.symbols"
	PeImports     Field = "pe.imports"
	PeTimestamp   Field = "pe.timestamp"
	PeBaseAddress Field = "pe.address.base"
	PeEntrypoint  Field = "pe.address.entrypoint"
	PeResources   Field = "pe.resources"

	KevtSeq         Field = "kevt.seq"
	KevtPID         Field = "kevt.pid"
	KevtTID         Field = "kevt.tid"
	KevtCPU         Field = "kevt.cpu"
	KevtDesc        Field = "kevt.desc"
	KevtHost        Field = "kevt.host"
	KevtTime        Field = "kevt.time"
	KevtTimeHour    Field = "kevt.time.h"
	KevtTimeMin     Field = "kevt.time.m"
	KevtTimeSec     Field = "kevt.time.s"
	KevtTimeNs      Field = "kevt.time.ns"
	KevtDate        Field = "kevt.date"
	KevtDateDay     Field = "kevt.date.d"
	KevtDateMonth   Field = "kevt.date.m"
	KevtDateYear    Field = "kevt.date.y"
	KevtDateTz      Field = "kevt.date.tz"
	KevtDateWeek    Field = "kevt.date.week"
	KevtDateWeekday Field = "kevt.date.weekday"
	KevtName        Field = "kevt.name"
	KevtCategory    Field = "kevt.category"
	KevtMeta        Field = "kevt.meta"
	KevtNparams     Field = "kevt.nparams"

	HandleID     Field = "handle.id"
	HandleObject Field = "handle.object"
	HandleName   Field = "handle.name"
	HandleType   Field = "handle.type"

	NetDIP        Field = "net.dip"
	NetSIP        Field = "net.sip"
	NetDport      Field = "net.dport"
	NetSport      Field = "net.sport"
	NetDportName  Field = "net.dport.name"
	NetSportName  Field = "net.sport.name"
	NetL4Proto    Field = "net.l4.proto"
	NetPacketSize Field = "net.size"

	FileObject    Field = "file.object"
	FileName      Field = "file.name"
	FileOperation Field = "file.operation"
	FileShareMask Field = "file.share.mask"
	FileIOSize    Field = "file.io.size"
	FileOffset    Field = "file.offset"
	FileType      Field = "file.type"

	RegistryKeyName   Field = "registry.key.name"
	RegistryKeyHandle Field = "registry.key.handle"
	RegistryValue     Field = "registry.value"
	RegistryValueType Field = "registry.value.type"
	RegistryStatus    Field = "registry.status"

	ImageBase           Field = "image.base.address"
	ImageSize           Field = "image.size"
	ImageChecksum       Field = "image.checksum"
	ImageDefaultAddress Field = "image.default.address"
	ImageName           Field = "image.name"
	ImagePID            Field = "image.pid"

	None Field = ""
)

// String casts the field type to string.
func (f Field) String() string { return string(f) }

// Subfield represents the type alias for the subfield.
type Subfield string

const (
	// SectionEntropy is the entropy value of the specific PE section
	SectionEntropy Subfield = "entropy"
	// SectionMD5Hash refers to the section md5 sum
	SectionMD5Hash Subfield = "md5"
	SectionSize    Subfield = "size"

	ModuleSize           Subfield = "size"
	ModuleChecksum       Subfield = "checksum"
	ModuleLocation       Subfield = "location"
	ModuleBaseAddress    Subfield = "address.base"
	ModuleDefaultAddress Subfield = "address.default"
)

const (
	PsEnvsSubfield      = "ps.envs["
	PsModsSubfield      = "ps.modules["
	PeSectionsSubfield  = "pe.sections["
	PeResourcesSubfield = "pe.resources["
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

	PsPid:         {PsPid, "process identifier", kparams.PID, []string{"ps.pid = 1024"}},
	PsPpid:        {PsPpid, "parent process identifier", kparams.PID, []string{"ps.ppid = 45"}},
	PsName:        {PsName, "process image name including the file extension", kparams.UnicodeString, []string{"ps.name contains 'firefox'"}},
	PsComm:        {PsComm, "process command line", kparams.UnicodeString, []string{"ps.comm contains 'java'"}},
	PsExe:         {PsExe, "full name of the process' executable", kparams.UnicodeString, []string{"ps.exe = 'C:\\Windows\\system32\\cmd.exe'"}},
	PsArgs:        {PsArgs, "process command line arguments", kparams.Slice, []string{"ps.args in ('/cdir', '/-C')"}},
	PsCwd:         {PsCwd, "process current working directory", kparams.UnicodeString, []string{"ps.cwd = 'C:\\Users\\Default'"}},
	PsSID:         {PsSID, "security identifier under which this process is run", kparams.UnicodeString, []string{"ps.sid contains 'SYSTEM'"}},
	PsSessionID:   {PsSessionID, "unique identifier for the current session", kparams.Int16, []string{"ps.sessionid = 1"}},
	PsEnvs:        {PsEnvs, "process environment variables", kparams.Slice, []string{"ps.envs in ('MOZ_CRASHREPORTER_DATA_DIRECTORY')"}},
	PsHandles:     {PsHandles, "allocated process handle names", kparams.Slice, []string{"ps.handles in ('\\BaseNamedObjects\\__ComCatalogCache__')"}},
	PsHandleTypes: {PsHandleTypes, "allocated process handle types", kparams.Slice, []string{"ps.handle.types in ('Key', 'Mutant', 'Section')"}},
	PsDTB:         {PsDTB, "process directory table base address", kparams.HexInt64, []string{"ps.dtb = '7ffe0000'"}},
	PsModules:     {PsModules, "modules loaded by the process", kparams.Slice, []string{"ps.modules in ('crypt32.dll', 'xul.dll')"}},

	ThreadBasePrio:    {ThreadBasePrio, "scheduler priority of the thread", kparams.Int8, []string{"thread.prio = 5"}},
	ThreadIOPrio:      {ThreadIOPrio, "I/O priority hint for scheduling I/O operations", kparams.Int8, []string{"thread.io.prio = 4"}},
	ThreadPagePrio:    {ThreadPagePrio, "memory page priority hint for memory pages accessed by the thread", kparams.Int8, []string{"thread.page.prio = 12"}},
	ThreadKstackBase:  {ThreadKstackBase, "base address of the thread's kernel space stack", kparams.HexInt64, []string{"thread.kstack.base = 'a65d800000'"}},
	ThreadKstackLimit: {ThreadKstackLimit, "limit of the thread's kernel space stack", kparams.HexInt64, []string{"thread.kstack.limit = 'a85d800000'"}},
	ThreadUstackBase:  {ThreadUstackBase, "base address of the thread's user space stack", kparams.HexInt64, []string{"thread.ustack.base = '7ffe0000'"}},
	ThreadUstackLimit: {ThreadUstackLimit, "limit of the thread's user space stack", kparams.HexInt64, []string{"thread.ustack.limit = '8ffe0000'"}},
	ThreadEntrypoint:  {ThreadEntrypoint, "starting address of the function to be executed by the thread", kparams.HexInt64, []string{"thread.entrypoint = '7efe0000'"}},

	ImageName:           {ImageName, "full image name", kparams.UnicodeString, []string{"image.name contains 'advapi32.dll'"}},
	ImageBase:           {ImageBase, "the base address of process in which the image is loaded", kparams.HexInt64, []string{"image.base.address = 'a65d800000'"}},
	ImageChecksum:       {ImageChecksum, "image checksum", kparams.Uint32, []string{"image.checksum = 746424"}},
	ImageSize:           {ImageSize, "image size", kparams.Uint32, []string{"image.size > 1024"}},
	ImageDefaultAddress: {ImageDefaultAddress, "default image address", kparams.HexInt64, []string{"image.default.address = '7efe0000'"}},

	FileObject:    {FileObject, "file object address", kparams.Uint64, []string{"file.object = 18446738026482168384"}},
	FileName:      {FileName, "full file name", kparams.UnicodeString, []string{"file.name contains 'mimikatz'"}},
	FileOperation: {FileOperation, "file operation", kparams.AnsiString, []string{"file.operation = 'open'"}},
	FileShareMask: {FileShareMask, "file share mask", kparams.AnsiString, []string{"file.share.mask = 'rw-'"}},
	FileIOSize:    {FileIOSize, "file I/O size", kparams.Uint32, []string{"file.io.size > 512"}},
	FileOffset:    {FileOffset, "file offset", kparams.Uint64, []string{"file.offset = 1024"}},
	FileType:      {FileType, "file type", kparams.AnsiString, []string{"file.type = 'directory'"}},

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
// the expected one and compares the subfields. If all checks pass, the full nested field literal
// is returned.
func Lookup(name string) Field {
	if _, ok := fields[Field(name)]; ok {
		return Field(name)
	}
	groups := subfieldRegexp.FindStringSubmatch(name)
	if len(groups) != 3 {
		return None
	}

	field := groups[1]
	subfield := groups[2]

	switch Field(field) {
	case PeSections:
		switch Subfield(subfield) {
		case SectionEntropy:
			return Field(name)
		case SectionMD5Hash:
			return Field(name)
		case SectionSize:
			return Field(name)
		}
	case PeResources:
		return Field(name)
	case PsEnvs:
		return Field(name)
	case PsModules:
		switch Subfield(subfield) {
		case ModuleSize:
			return Field(ModuleSize)
		case ModuleChecksum:
			return Field(ModuleChecksum)
		case ModuleDefaultAddress:
			return Field(ModuleDefaultAddress)
		case ModuleBaseAddress:
			return Field(ModuleBaseAddress)
		case ModuleLocation:
			return Field(ModuleLocation)
		}
	}

	return None
}
