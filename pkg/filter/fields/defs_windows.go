//go:build windows

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
	"unicode"

	"github.com/rabbitstack/fibratus/pkg/event/params"
)

// isNumber is the field argument validation function that
// returns true if all characters are digits.
var isNumber = func(s string) bool {
	for _, c := range s {
		if !unicode.IsNumber(c) {
			return false
		}
	}
	return true
}

func init() {
	fields[KevtPID] = FieldInfo{KevtPID, "process identifier generating the event", params.Uint32, []string{"kevt.pid = 6"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtPID}}, nil}
	fields[KevtTID] = FieldInfo{KevtTID, "thread identifier generating the event", params.Uint32, []string{"kevt.tid = 1024"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtTID}}, nil}
	fields[KevtSeq] = FieldInfo{KevtSeq, "event sequence number", params.Uint64, []string{"kevt.seq > 666"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtSeq}}, nil}
	fields[KevtCPU] = FieldInfo{KevtCPU, "logical processor core where the event was generated", params.Uint8, []string{"kevt.cpu = 2"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtCPU}}, nil}
	fields[KevtName] = FieldInfo{KevtName, "symbolical event name", params.AnsiString, []string{"kevt.name = 'CreateThread'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtName}}, nil}
	fields[KevtCategory] = FieldInfo{KevtCategory, "event category", params.AnsiString, []string{"kevt.category = 'registry'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtCategory}}, nil}
	fields[KevtDesc] = FieldInfo{KevtDesc, "event description", params.AnsiString, []string{"kevt.desc contains 'Creates a new process'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDesc}}, nil}
	fields[KevtHost] = FieldInfo{KevtHost, "host name on which the event was produced", params.UnicodeString, []string{"kevt.host contains 'kitty'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtHost}}, nil}
	fields[KevtTime] = FieldInfo{KevtTime, "event timestamp as a time string", params.Time, []string{"kevt.time = '17:05:32'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtTime}}, nil}
	fields[KevtTimeHour] = FieldInfo{KevtTimeHour, "hour within the day on which the event occurred", params.Time, []string{"kevt.time.h = 23"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtTimeHour}}, nil}
	fields[KevtTimeMin] = FieldInfo{KevtTimeMin, "minute offset within the hour on which the event occurred", params.Time, []string{"kevt.time.m = 54"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtTimeMin}}, nil}
	fields[KevtTimeSec] = FieldInfo{KevtTimeSec, "second offset within the minute  on which the event occurred", params.Time, []string{"kevt.time.s = 0"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtTimeSec}}, nil}
	fields[KevtTimeNs] = FieldInfo{KevtTimeNs, "nanoseconds specified by event timestamp", params.Int64, []string{"kevt.time.ns > 1591191629102337000"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtTimeNs}}, nil}
	fields[KevtDate] = FieldInfo{KevtDate, "event timestamp as a date string", params.Time, []string{"kevt.date = '2018-03-03'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDate}}, nil}
	fields[KevtDateDay] = FieldInfo{KevtDateDay, "day of the month on which the event occurred", params.Time, []string{"kevt.date.d = 12"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateDay}}, nil}
	fields[KevtDateMonth] = FieldInfo{KevtDateMonth, "month of the year on which the event occurred", params.Time, []string{"kevt.date.m = 11"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateMonth}}, nil}
	fields[KevtDateYear] = FieldInfo{KevtDateYear, "year on which the event occurred", params.Uint32, []string{"kevt.date.y = 2020"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateYear}}, nil}
	fields[KevtDateTz] = FieldInfo{KevtDateTz, "time zone associated with the event timestamp", params.AnsiString, []string{"kevt.date.tz = 'UTC'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateTz}}, nil}
	fields[KevtDateWeek] = FieldInfo{KevtDateWeek, "week number within the year on which the event occurred", params.Uint8, []string{"kevt.date.week = 2"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateWeek}}, nil}
	fields[KevtDateWeekday] = FieldInfo{KevtDateWeekday, "week day on which the event occurred", params.AnsiString, []string{"kevt.date.weekday = 'Monday'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtDateWeekday}}, nil}
	fields[KevtNparams] = FieldInfo{KevtNparams, "number of parameters", params.Int8, []string{"kevt.nparams > 2"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtNparams}}, nil}
	fields[KevtArg] = FieldInfo{KevtArg, "event parameter", params.Object, []string{"kevt.arg[cmdline] istartswith 'C:\\Windows'"}, &Deprecation{Since: "3.0.0", Fields: []Field{EvtArg}}, &Argument{Optional: false, Pattern: "[a-z0-9_]+", ValidationFunc: func(s string) bool {
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
	}}}
	fields[PsPid] = FieldInfo{PsPid, "process identifier", params.PID, []string{"ps.pid = 1024"}, nil, nil}
	fields[PsPpid] = FieldInfo{PsPpid, "parent process identifier", params.PID, []string{"ps.ppid = 45"}, nil, nil}
	fields[PsParentPid] = FieldInfo{PsParentPid, "parent process id", params.Uint32, []string{"ps.parent.pid = 4"}, nil, nil}
	fields[EvtIsDirectSyscall] = FieldInfo{EvtIsDirectSyscall, "indicates if the event is performing a direct syscall", params.Bool, []string{"evt.is_direct_syscall = true"}, nil, nil}
	fields[EvtIsIndirectSyscall] = FieldInfo{EvtIsIndirectSyscall, "indicates if the event is performing an indirect syscall", params.Bool, []string{"evt.is_indirect_syscall = true"}, nil, nil}
	fields[PsComm] = FieldInfo{PsComm, "process command line", params.UnicodeString, []string{"ps.comm contains 'java'"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsCmdline}}, nil}
	fields[PsSID] = FieldInfo{PsSID, "security identifier under which this process is run", params.UnicodeString, []string{"ps.sid contains 'SYSTEM'"}, nil, nil}
	fields[PsSessionID] = FieldInfo{PsSessionID, "unique identifier for the current session", params.Int16, []string{"ps.sessionid = 1"}, nil, nil}
	fields[PsDomain] = FieldInfo{PsDomain, "process domain", params.UnicodeString, []string{"ps.domain contains 'SERVICE'"}, nil, nil}
	fields[PsHandleNames] = FieldInfo{PsHandleNames, "allocated process handle names", params.Slice, []string{"ps.handles in ('\\BaseNamedObjects\\__ComCatalogCache__')"}, nil, nil}
	fields[PsHandleTypes] = FieldInfo{PsHandleTypes, "allocated process handle types", params.Slice, []string{"ps.handle.types in ('Key', 'Mutant', 'Section')"}, nil, nil}
	fields[PsDTB] = FieldInfo{PsDTB, "process directory table base address", params.Address, []string{"ps.dtb = '7ffe0000'"}, nil, nil}
	fields[PsModuleNames] = FieldInfo{PsModuleNames, "modules loaded by the process", params.Slice, []string{"ps.modules in ('crypt32.dll', 'xul.dll')"}, nil, nil}
	fields[PsParentComm] = FieldInfo{PsParentComm, "parent process command line", params.UnicodeString, []string{"ps.parent.comm contains 'java'"}, &Deprecation{Since: "1.10.0", Fields: []Field{PsParentCmdline}}, nil}
	fields[PsParentArgs] = FieldInfo{PsParentArgs, "parent process command line arguments", params.Slice, []string{"ps.parent.args in ('/cdir', '/-C')"}, nil, nil}
	fields[PsParentCwd] = FieldInfo{PsParentCwd, "parent process current working directory", params.UnicodeString, []string{"ps.parent.cwd = 'C:\\Temp'"}, nil, nil}
	fields[PsParentSID] = FieldInfo{PsParentSID, "security identifier under which the parent process is run", params.UnicodeString, []string{"ps.parent.sid contains 'SYSTEM'"}, nil, nil}
	fields[PsParentDomain] = FieldInfo{PsParentDomain, "parent process domain", params.UnicodeString, []string{"ps.parent.domain contains 'SERVICE'"}, nil, nil}
	fields[PsParentUsername] = FieldInfo{PsParentUsername, "parent process username", params.UnicodeString, []string{"ps.parent.username contains 'system'"}, nil, nil}
	fields[PsParentSessionID] = FieldInfo{PsParentSessionID, "unique identifier for the current session of parent process", params.Int16, []string{"ps.parent.sessionid = 1"}, nil, nil}
	fields[PsParentEnvs] = FieldInfo{PsParentEnvs, "parent process environment variables", params.Slice, []string{"ps.parent.envs in ('MOZ_CRASHREPORTER_DATA_DIRECTORY')"}, nil, nil}
	fields[PsParentHandles] = FieldInfo{PsParentHandles, "allocated parent process handle names", params.Slice, []string{"ps.parent.handles in ('\\BaseNamedObjects\\__ComCatalogCache__')"}, nil, nil}
	fields[PsParentHandleTypes] = FieldInfo{PsParentHandleTypes, "allocated parent process handle types", params.Slice, []string{"ps.parent.handle.types in ('File', 'SymbolicLink')"}, nil, nil}
	fields[PsParentDTB] = FieldInfo{PsParentDTB, "parent process directory table base address", params.Address, []string{"ps.parent.dtb = '7ffe0000'"}, nil, nil}
	fields[PsAccessMask] = FieldInfo{PsAccessMask, "process desired access rights", params.AnsiString, []string{"ps.access.mask = '0x1400'"}, nil, nil}
	fields[PsAccessMaskNames] = FieldInfo{PsAccessMaskNames, "process desired access rights as a string list", params.Slice, []string{"ps.access.mask.names in ('SUSPEND_RESUME')"}, nil, nil}
	fields[PsAccessStatus] = FieldInfo{PsAccessStatus, "process access status", params.UnicodeString, []string{"ps.access.status = 'access is denied.'"}, nil, nil}
	fields[PsUUID] = FieldInfo{PsUUID, "unique process identifier", params.Uint64, []string{"ps.uuid > 6000054355"}, nil, nil}
	fields[PsParentUUID] = FieldInfo{PsParentUUID, "unique parent process identifier", params.Uint64, []string{"ps.parent.uuid > 6000054355"}, nil, nil}
	fields[PsIsWOW64Field] = FieldInfo{PsIsWOW64Field, "indicates if the process generating the event is a 32-bit process created in 64-bit Windows system", params.Bool, []string{"ps.is_wow64"}, nil, nil}
	fields[PsIsPackagedField] = FieldInfo{PsIsPackagedField, "indicates if the process generating the event is packaged with the MSIX technology", params.Bool, []string{"ps.is_packaged"}, nil, nil}
	fields[PsIsProtectedField] = FieldInfo{PsIsProtectedField, "indicates if the process generating the event is a protected process", params.Bool, []string{"ps.is_protected"}, nil, nil}
	fields[PsParentIsWOW64Field] = FieldInfo{PsParentIsWOW64Field, "indicates if the parent process generating the event is a 32-bit process created in 64-bit Windows system", params.Bool, []string{"ps.parent.is_wow64"}, nil, nil}
	fields[PsParentIsPackagedField] = FieldInfo{PsParentIsPackagedField, "indicates if the parent process generating the event is packaged with the MSIX technology", params.Bool, []string{"ps.parent.is_packaged"}, nil, nil}
	fields[PsParentIsProtectedField] = FieldInfo{PsParentIsProtectedField, "indicates if the the parent process generating the event is a protected process", params.Bool, []string{"ps.parent.is_protected"}, nil, nil}
	fields[PsAncestor] = FieldInfo{PsAncestor, "the process ancestor name", params.UnicodeString, []string{"ps.ancestor[1] = 'svchost.exe'", "ps.ancestor in ('winword.exe')"}, nil, &Argument{Optional: true, Pattern: "[0-9]+", ValidationFunc: isNumber}}
	fields[PsTokenIntegrityLevel] = FieldInfo{PsTokenIntegrityLevel, "process token integrity level", params.UnicodeString, []string{"ps.token.integrity_level = 'SYSTEM'"}, nil, nil}
	fields[PsTokenIsElevated] = FieldInfo{PsTokenIsElevated, "indicates if the process token is elevated", params.Bool, []string{"ps.token.is_elevated = true"}, nil, nil}
	fields[PsTokenElevationType] = FieldInfo{PsTokenElevationType, "process token elevation type", params.AnsiString, []string{"ps.token.elevation_type = 'LIMITED'"}, nil, nil}
	fields[PsParentTokenIntegrityLevel] = FieldInfo{PsParentTokenIntegrityLevel, "parent process token integrity level", params.UnicodeString, []string{"ps.parent.token.integrity_level = 'HIGH'"}, nil, nil}
	fields[PsParentTokenIsElevated] = FieldInfo{PsParentTokenIsElevated, "indicates if the parent process token is elevated", params.Bool, []string{"ps.parent.token.is_elevated = true"}, nil, nil}
	fields[PsParentTokenElevationType] = FieldInfo{PsParentTokenElevationType, "parent process token elevation type", params.AnsiString, []string{"ps.parent.token.elevation_type = 'LIMITED'"}, nil, nil}
	fields[PsSignatureExists] = FieldInfo{PsSignatureExists, "indicates if the process executable has a valid signature", params.Bool, []string{"ps.signature.exists"}, nil, nil}
	fields[PsSignatureTrusted] = FieldInfo{PsSignatureTrusted, "indicates if the process executable signature certificate chain is trusted", params.Bool, []string{"ps.signature.trusted"}, nil, nil}
	fields[PsSignatureSerial] = FieldInfo{PsSignatureSerial, "represents signature serial number", params.UnicodeString, []string{"ps.signature.serial = '330000023241fb59996dcc4dff000000000232'"}, nil, nil}
	fields[PsSignatureSubject] = FieldInfo{PsSignatureSubject, "represents signature subject", params.UnicodeString, []string{"ps.signature.subject contains 'Washington, Redmond, Microsoft Corporation'"}, nil, nil}
	fields[PsSignatureIssuer] = FieldInfo{PsSignatureIssuer, "represents signature CA", params.UnicodeString, []string{"ps.signature.issuer contains 'Washington, Redmond, Microsoft Corporation'"}, nil, nil}
	fields[PsSignatureAfter] = FieldInfo{PsSignatureAfter, "represents certificate expiration date", params.Time, []string{"ps.signature.after contains '2024-02-01 00:05:42 +0000 UTC'"}, nil, nil}
	fields[PsSignatureBefore] = FieldInfo{PsSignatureBefore, "represents certificate enrollment date", params.Time, []string{"ps.signature.before contains '2024-02-01 00:05:42 +0000 UTC'"}, nil, nil}
	fields[PsPeNumSections] = FieldInfo{PsPeNumSections, "number of PE sections", params.Uint16, []string{"ps.pe.nsections < 5"}, nil, nil}
	fields[PsPeNumSymbols] = FieldInfo{PsPeNumSymbols, "number of entries in the symbol table", params.Uint32, []string{"ps.pe.nsymbols > 230"}, nil, nil}
	fields[PsPeBaseAddress] = FieldInfo{PsPeBaseAddress, "executable base address", params.Address, []string{"ps.pe.address.base = '140000000'"}, nil, nil}
	fields[PsPeEntrypoint] = FieldInfo{PsPeEntrypoint, "address of the entrypoint function", params.Address, []string{"ps.pe.address.entrypoint = '20110'"}, nil, nil}
	fields[PsPeSymbols] = FieldInfo{PsPeSymbols, "imported symbols", params.Slice, []string{"ps.pe.symbols in ('GetTextFaceW', 'GetProcessHeap')"}, nil, nil}
	fields[PsPeImports] = FieldInfo{PsPeImports, "imported dynamic linked libraries", params.Slice, []string{"ps.pe.imports in ('msvcrt.dll', 'GDI32.dll'"}, nil, nil}
	fields[PsPeResources] = FieldInfo{PsPeResources, "version resources", params.Map, []string{"ps.pe.resources[FileDescription] = 'Notepad'"}, nil, &Argument{Optional: true, Pattern: "[a-zA-Z0-9_]+", ValidationFunc: func(s string) bool {
		for _, c := range s {
			switch {
			case unicode.IsLower(c):
			case unicode.IsUpper(c):
			case unicode.IsNumber(c):
			case c == '_':
			default:
				return false
			}
		}
		return true
	}}}
	fields[PsPeCompany] = FieldInfo{PsPeCompany, "internal company name of the file provided at compile-time", params.UnicodeString, []string{"ps.pe.company = 'Microsoft Corporation'"}, nil, nil}
	fields[PsPeCopyright] = FieldInfo{PsPeCopyright, "copyright notice for the file emitted at compile-time", params.UnicodeString, []string{"ps.pe.copyright = '© Microsoft Corporation'"}, nil, nil}
	fields[PsPeDescription] = FieldInfo{PsPeDescription, "internal description of the file provided at compile-time", params.UnicodeString, []string{"ps.pe.description = 'Notepad'"}, nil, nil}
	fields[PsPeFileName] = FieldInfo{PsPeFileName, "original file name supplied at compile-time", params.UnicodeString, []string{"ps.pe.file.name = 'NOTEPAD.EXE'"}, nil, nil}
	fields[PsPeFileVersion] = FieldInfo{PsPeFileVersion, "file version supplied at compile-time", params.UnicodeString, []string{"ps.pe.file.version = '10.0.18362.693 (WinBuild.160101.0800)'"}, nil, nil}
	fields[PsPeProduct] = FieldInfo{PsPeProduct, "internal product name of the file provided at compile-time", params.UnicodeString, []string{"ps.pe.product = 'Microsoft® Windows® Operating System'"}, nil, nil}
	fields[PsPeProductVersion] = FieldInfo{PsPeProductVersion, "internal product version of the file provided at compile-time", params.UnicodeString, []string{"ps.pe.product.version = '10.0.18362.693'"}, nil, nil}
	fields[PsPeImphash] = FieldInfo{PsPeImphash, "import hash", params.AnsiString, []string{"pe.impash = '5d3861c5c547f8a34e471ba273a732b2'"}, nil, nil}
	fields[PsPeIsDotnet] = FieldInfo{PsPeIsDotnet, "indicates if PE contains CLR data", params.Bool, []string{"ps.pe.is_dotnet"}, nil, nil}
	fields[PsPeAnomalies] = FieldInfo{PsPeAnomalies, "contains PE anomalies detected during parsing", params.Slice, []string{"ps.pe.anomalies in ('number of sections is 0')"}, nil, nil}
	fields[PsPeIsModified] = FieldInfo{PsPeIsModified, "indicates if disk and in-memory PE headers differ", params.Bool, []string{"ps.pe.is_modified"}, nil, nil}
	fields[ThreadBasePrio] = FieldInfo{ThreadBasePrio, "scheduler priority of the thread", params.Int8, []string{"thread.prio = 5"}, nil, nil}
	fields[ThreadIOPrio] = FieldInfo{ThreadIOPrio, "I/O priority hint for scheduling I/O operations", params.Int8, []string{"thread.io.prio = 4"}, nil, nil}
	fields[ThreadPagePrio] = FieldInfo{ThreadPagePrio, "memory page priority hint for memory pages accessed by the thread", params.Int8, []string{"thread.page.prio = 12"}, nil, nil}
	fields[ThreadKstackBase] = FieldInfo{ThreadKstackBase, "base address of the thread's kernel space stack", params.Address, []string{"thread.kstack.base = 'a65d800000'"}, nil, nil}
	fields[ThreadKstackLimit] = FieldInfo{ThreadKstackLimit, "limit of the thread's kernel space stack", params.Address, []string{"thread.kstack.limit = 'a85d800000'"}, nil, nil}
	fields[ThreadUstackBase] = FieldInfo{ThreadUstackBase, "base address of the thread's user space stack", params.Address, []string{"thread.ustack.base = '7ffe0000'"}, nil, nil}
	fields[ThreadUstackLimit] = FieldInfo{ThreadUstackLimit, "limit of the thread's user space stack", params.Address, []string{"thread.ustack.limit = '8ffe0000'"}, nil, nil}
	fields[ThreadEntrypoint] = FieldInfo{ThreadEntrypoint, "starting address of the function to be executed by the thread", params.Address, []string{"thread.entrypoint = '7efe0000'"}, &Deprecation{Since: "2.3.0", Fields: []Field{ThreadStartAddress}}, nil}
	fields[ThreadStartAddress] = FieldInfo{ThreadStartAddress, "thread start address", params.Address, []string{"thread.start_address = '7efe0000'"}, nil, nil}
	fields[ThreadStartAddressSymbol] = FieldInfo{ThreadStartAddressSymbol, "thread start address symbol", params.UnicodeString, []string{"thread.start_address.symbol = 'LoadModule'"}, nil, nil}
	fields[ThreadStartAddressModule] = FieldInfo{ThreadStartAddressModule, "thread start address module", params.UnicodeString, []string{"thread.start_address.module endswith 'kernel32.dll'"}, nil, nil}
	fields[ThreadPID] = FieldInfo{ThreadPID, "the process identifier where the thread is created", params.Uint32, []string{"evt.pid != thread.pid"}, nil, nil}
	fields[ThreadTEB] = FieldInfo{ThreadTEB, "the base address of the thread environment block", params.Address, []string{"thread.teb_address = '8f30893000'"}, nil, nil}
	fields[ThreadAccessMask] = FieldInfo{ThreadAccessMask, "thread desired access rights", params.AnsiString, []string{"thread.access.mask = '0x1fffff'"}, nil, nil}
	fields[ThreadAccessMaskNames] = FieldInfo{ThreadAccessMaskNames, "thread desired access rights as a string list", params.Slice, []string{"thread.access.mask.names in ('IMPERSONATE')"}, nil, nil}
	fields[ThreadAccessStatus] = FieldInfo{ThreadAccessStatus, "thread access status", params.UnicodeString, []string{"thread.access.status = 'success'"}, nil, nil}
	fields[ThreadCallstackSummary] = FieldInfo{ThreadCallstackSummary, "callstack summary", params.UnicodeString, []string{"thread.callstack.summary contains 'ntdll.dll|KERNELBASE.dll'"}, nil, nil}
	fields[ThreadCallstackKernelSummary] = FieldInfo{ThreadCallstackKernelSummary, "kernel thread callstack summary", params.UnicodeString, []string{"thread.callstack.kernel_summary contains 'fileinfo.sys|ntoskrnl.exe|FLTMGR.SYS|ntoskrnl.exe'"}, nil, nil}
	fields[ThreadCallstackDetail] = FieldInfo{ThreadCallstackDetail, "detailed information of each stack frame", params.UnicodeString, []string{"thread.callstack.detail contains 'KERNELBASE.dll!CreateProcessW'"}, nil, nil}
	fields[ThreadCallstackModules] = FieldInfo{ThreadCallstackModules, "list of modules comprising the callstack", params.Slice, []string{"thread.callstack.modules in ('C:\\WINDOWS\\System32\\KERNELBASE.dll')", "base(thread.callstack.modules[7]) = 'ntdll.dll'"}, nil, &Argument{Optional: true, Pattern: "[0-9]+", ValidationFunc: isNumber}}
	fields[ThreadCallstackSymbols] = FieldInfo{ThreadCallstackSymbols, "list of symbols comprising the callstack", params.Slice, []string{"thread.callstack.symbols in ('ntdll.dll!NtCreateProcess')", "thread.callstack.symbols[3] = 'ntdll!NtCreateProcess'"}, nil, &Argument{Optional: true, Pattern: "[0-9]+", ValidationFunc: isNumber}}
	fields[ThreadCallstackAllocationSizes] = FieldInfo{ThreadCallstackAllocationSizes, "allocation sizes of private pages", params.Slice, []string{"thread.callstack.allocation_sizes > 10000"}, nil, nil}
	fields[ThreadCallstackProtections] = FieldInfo{ThreadCallstackProtections, "page protections masks of each frame", params.Slice, []string{"thread.callstack.protections in ('RWX', 'WX')"}, nil, nil}
	fields[ThreadCallstackCallsiteLeadingAssembly] = FieldInfo{ThreadCallstackCallsiteLeadingAssembly, "callsite leading assembly instructions", params.Slice, []string{"thread.callstack.callsite_leading_assembly in ('mov r10,rcx', 'syscall')"}, nil, nil}
	fields[ThreadCallstackCallsiteTrailingAssembly] = FieldInfo{ThreadCallstackCallsiteTrailingAssembly, "callsite trailing assembly instructions", params.Slice, []string{"thread.callstack.callsite_trailing_assembly in ('add esp, 0xab')"}, nil, nil}
	fields[ThreadCallstackIsUnbacked] = FieldInfo{ThreadCallstackIsUnbacked, "indicates if the callstack contains unbacked regions", params.Bool, []string{"thread.callstack.is_unbacked"}, nil, nil}
	fields[ThreadCallstackAddresses] = FieldInfo{ThreadCallstackAddresses, "list of all stack return addresses", params.Slice, []string{"thread.callstack.addresses in ('7ffb5c1d0396')"}, nil, nil}
	fields[ThreadCallstackFinalUserModuleName] = FieldInfo{ThreadCallstackFinalUserModuleName, "final user space stack frame module name", params.UnicodeString, []string{"thread.callstack.final_user_module.name != 'ntdll.dll'"}, nil, nil}
	fields[ThreadCallstackFinalUserModulePath] = FieldInfo{ThreadCallstackFinalUserModulePath, "final user space stack frame module path", params.UnicodeString, []string{"thread.callstack.final_user_module.path imatches '?:\\Windows\\System32\\ntdll.dll'"}, nil, nil}
	fields[ThreadCallstackFinalUserSymbolName] = FieldInfo{ThreadCallstackFinalUserSymbolName, "final user space stack symbol name", params.UnicodeString, []string{"thread.callstack.final_user_symbol.name imatches 'CreateProcess*'"}, nil, nil}
	fields[ThreadCallstackFinalKernelModuleName] = FieldInfo{ThreadCallstackFinalKernelModuleName, "final kernel space stack frame module name", params.UnicodeString, []string{"thread.callstack.final_kernel_module.name = 'FLTMGR.SYS'"}, nil, nil}
	fields[ThreadCallstackFinalKernelModulePath] = FieldInfo{ThreadCallstackFinalKernelModulePath, "final kernel space stack frame module path", params.UnicodeString, []string{"thread.callstack.final_kernel_module.path imatches '?:\\WINDOWS\\System32\\drivers\\FLTMGR.SYS'"}, nil, nil}
	fields[ThreadCallstackFinalKernelSymbolName] = FieldInfo{ThreadCallstackFinalKernelSymbolName, "final kernel space stack symbol name", params.UnicodeString, []string{"thread.callstack.final_kernel_symbol.name = 'FltGetStreamContext'"}, nil, nil}
	fields[ThreadCallstackFinalUserModuleSignatureExists] = FieldInfo{ThreadCallstackFinalUserModuleSignatureExists, "signature status of the final user space stack frame module", params.Bool, []string{"thread.callstack.final_user_module.signature.exists = true"}, nil, nil}
	fields[ThreadCallstackFinalUserModuleSignatureTrusted] = FieldInfo{ThreadCallstackFinalUserModuleSignatureTrusted, "signature trust status of the final user space stack frame module", params.Bool, []string{"thread.callstack.final_user_module.signature.trusted = true"}, nil, nil}
	fields[ThreadCallstackFinalUserModuleSignatureIssuer] = FieldInfo{ThreadCallstackFinalUserModuleSignatureIssuer, "final user space stack frame module signature certificate issuer", params.UnicodeString, []string{"thread.callstack.final_user_module.signature.issuer imatches '*Microsoft Corporation*'"}, nil, nil}
	fields[ThreadCallstackFinalUserModuleSignatureSubject] = FieldInfo{ThreadCallstackFinalUserModuleSignatureSubject, "final user space stack frame module signature certificate subject", params.UnicodeString, []string{"thread.callstack.final_user_module.signature.subject imatches '*Microsoft Windows*'"}, nil, nil}
	fields[ImagePath] = FieldInfo{ImagePath, "full image path", params.UnicodeString, []string{"image.path = 'C:\\Windows\\System32\\advapi32.dll'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModulePath}}, nil}
	fields[ImageName] = FieldInfo{ImageName, "image name", params.UnicodeString, []string{"image.name = 'advapi32.dll'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleName}}, nil}
	fields[ImageBase] = FieldInfo{ImageBase, "the base address of process in which the image is loaded", params.Address, []string{"image.base.address = 'a65d800000'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleBase}}, nil}
	fields[ImageChecksum] = FieldInfo{ImageChecksum, "image checksum", params.Uint32, []string{"image.checksum = 746424"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleChecksum}}, nil}
	fields[ImageSize] = FieldInfo{ImageSize, "image size", params.Uint32, []string{"image.size > 1024"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleSize}}, nil}
	fields[ImageDefaultAddress] = FieldInfo{ImageDefaultAddress, "default image address", params.Address, []string{"image.default.address = '7efe0000'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleDefaultAddress}}, nil}
	fields[ImagePID] = FieldInfo{ImagePID, "target process identifier", params.Uint32, []string{"image.pid = 80"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModulePID}}, nil}
	fields[ImageSignatureType] = FieldInfo{ImageSignatureType, "image signature type", params.AnsiString, []string{"image.signature.type != 'NONE'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleSignatureType}}, nil}
	fields[ImageSignatureLevel] = FieldInfo{ImageSignatureLevel, "image signature level", params.AnsiString, []string{"image.signature.level = 'AUTHENTICODE'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleSignatureLevel}}, nil}
	fields[ImageCertSerial] = FieldInfo{ImageCertSerial, "image certificate serial number", params.UnicodeString, []string{"image.cert.serial = '330000023241fb59996dcc4dff000000000232'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleSignatureSerial}}, nil}
	fields[ImageCertSubject] = FieldInfo{ImageCertSubject, "image certificate subject", params.UnicodeString, []string{"image.cert.subject contains 'Washington, Redmond, Microsoft Corporation'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleSignatureSubject}}, nil}
	fields[ImageCertIssuer] = FieldInfo{ImageCertIssuer, "image certificate CA", params.UnicodeString, []string{"image.cert.issuer contains 'Washington, Redmond, Microsoft Corporation'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleSignatureIssuer}}, nil}
	fields[ImageCertAfter] = FieldInfo{ImageCertAfter, "image certificate expiration date", params.Time, []string{"image.cert.after contains '2024-02-01 00:05:42 +0000 UTC'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleSignatureAfter}}, nil}
	fields[ImageCertBefore] = FieldInfo{ImageCertBefore, "image certificate enrollment date", params.Time, []string{"image.cert.before contains '2024-02-01 00:05:42 +0000 UTC'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleSignatureBefore}}, nil}
	fields[ImageIsDLL] = FieldInfo{ImageIsDLL, "indicates if the loaded image is a DLL", params.Bool, []string{"image.is_dll'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleIsDLL}}, nil}
	fields[ImageIsDriver] = FieldInfo{ImageIsDriver, "indicates if the loaded image is a driver", params.Bool, []string{"image.is_driver'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleIsDriver}}, nil}
	fields[ImageIsExecutable] = FieldInfo{ImageIsExecutable, "indicates if the loaded image is an executable", params.Bool, []string{"image.is_exec'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleIsExecutable}}, nil}
	fields[ImageIsDotnet] = FieldInfo{ImageIsDotnet, "indicates if the loaded image is a .NET assembly", params.Bool, []string{"image.is_dotnet'"}, &Deprecation{Since: "3.0.0", Fields: []Field{ModuleIsDotnet}}, nil}
	fields[ModulePath] = FieldInfo{ModulePath, "full module path", params.UnicodeString, []string{"module.path = 'C:\\Windows\\System32\\advapi32.dll'"}, nil, nil}
	fields[ModulePathStem] = FieldInfo{ModulePathStem, "module path stem", params.UnicodeString, []string{"module.path.stem = 'C:\\Windows\\System32\\advapi32'"}, nil, nil}
	fields[ModuleName] = FieldInfo{ModuleName, "module name", params.UnicodeString, []string{"module.name = 'advapi32.dll'"}, nil, nil}
	fields[ModuleBase] = FieldInfo{ModuleBase, "the base address of process in which the module is loaded", params.Address, []string{"module.base.address = 'a65d800000'"}, nil, nil}
	fields[ModuleChecksum] = FieldInfo{ModuleChecksum, "module checksum", params.Uint32, []string{"module.checksum = 746424"}, nil, nil}
	fields[ModuleSize] = FieldInfo{ModuleSize, "module size", params.Uint32, []string{"module.size > 1024"}, nil, nil}
	fields[ModuleDefaultAddress] = FieldInfo{ModuleDefaultAddress, "default module address", params.Address, []string{"module.default_address = '7efe0000'"}, nil, nil}
	fields[ModulePID] = FieldInfo{ModulePID, "target process identifier", params.Uint32, []string{"module.pid = 80"}, nil, nil}
	fields[ModuleSignatureType] = FieldInfo{ModuleSignatureType, "module signature type", params.AnsiString, []string{"module.signature.type != 'NONE'"}, nil, nil}
	fields[ModuleSignatureLevel] = FieldInfo{ModuleSignatureLevel, "module signature level", params.AnsiString, []string{"module.signature.level = 'AUTHENTICODE'"}, nil, nil}
	fields[ModuleSignatureExists] = FieldInfo{ModuleSignatureExists, "indicates if the module is signed", params.Bool, []string{"module.signature.exists = true"}, nil, nil}
	fields[ModuleSignatureTrusted] = FieldInfo{ModuleSignatureTrusted, "indicates if the module signature is trusted", params.Bool, []string{"module.signature.trusted = false"}, nil, nil}
	fields[ModuleSignatureSerial] = FieldInfo{ModuleSignatureSerial, "module certificate serial number", params.UnicodeString, []string{"module.signature.serial = '330000023241fb59996dcc4dff000000000232'"}, nil, nil}
	fields[ModuleSignatureSubject] = FieldInfo{ModuleSignatureSubject, "module certificate subject", params.UnicodeString, []string{"module.signature.subject contains 'Washington, Redmond, Microsoft Corporation'"}, nil, nil}
	fields[ModuleSignatureIssuer] = FieldInfo{ModuleSignatureIssuer, "module certificate CA", params.UnicodeString, []string{"module.signature.issuer contains 'Washington, Redmond, Microsoft Corporation'"}, nil, nil}
	fields[ModuleSignatureAfter] = FieldInfo{ModuleSignatureAfter, "module certificate expiration date", params.Time, []string{"module.signature.after contains '2024-02-01 00:05:42 +0000 UTC'"}, nil, nil}
	fields[ModuleSignatureBefore] = FieldInfo{ModuleSignatureBefore, "module certificate enrollment date", params.Time, []string{"module.signature.before contains '2024-02-01 00:05:42 +0000 UTC'"}, nil, nil}
	fields[ModuleIsDLL] = FieldInfo{ModuleIsDLL, "indicates if the loaded module is a DLL", params.Bool, []string{"module.is_dll'"}, nil, nil}
	fields[ModuleIsDriver] = FieldInfo{ModuleIsDriver, "indicates if the loaded module is a driver", params.Bool, []string{"module.is_driver'"}, nil, nil}
	fields[ModuleIsExecutable] = FieldInfo{ModuleIsExecutable, "indicates if the loaded module is an executable", params.Bool, []string{"module.is_exec'"}, nil, nil}
	fields[ModuleIsDotnet] = FieldInfo{ModuleIsDotnet, "indicates if the loaded module is a .NET assembly", params.Bool, []string{"module.pe.is_dotnet'"}, nil, nil}
	fields[DllPath] = FieldInfo{DllPath, "full dll path", params.UnicodeString, []string{"dll.path = 'C:\\Windows\\System32\\advapi32.dll'"}, nil, nil}
	fields[DllPathStem] = FieldInfo{DllPathStem, "dll path stem", params.UnicodeString, []string{"dll.path.stem = 'C:\\Windows\\System32\\advapi32'"}, nil, nil}
	fields[DllName] = FieldInfo{DllName, "module name", params.UnicodeString, []string{"dll.name = 'advapi32.dll'"}, nil, nil}
	fields[DllBase] = FieldInfo{DllBase, "the base address of process in which the DLL is loaded", params.Address, []string{"dll.base = 'a65d800000'"}, nil, nil}
	fields[DllSize] = FieldInfo{DllSize, "dll virtual mapped size", params.Uint32, []string{"dll.size > 1024"}, nil, nil}
	fields[DllPID] = FieldInfo{DllPID, "target process identifier", params.Uint32, []string{"dll.pid = 80"}, nil, nil}
	fields[DllSignatureType] = FieldInfo{DllSignatureType, "dll signature type", params.AnsiString, []string{"dll.signature.type != 'NONE'"}, nil, nil}
	fields[DllSignatureLevel] = FieldInfo{DllSignatureLevel, "dll signature level", params.AnsiString, []string{"dll.signature.level = 'AUTHENTICODE'"}, nil, nil}
	fields[DllSignatureExists] = FieldInfo{DllSignatureExists, "indicates if the dll is signed", params.Bool, []string{"dll.signature.exists = true"}, nil, nil}
	fields[DllSignatureTrusted] = FieldInfo{DllSignatureTrusted, "indicates if the dll signature is trusted", params.Bool, []string{"dll.signature.trusted = false"}, nil, nil}
	fields[DllSignatureSerial] = FieldInfo{DllSignatureSerial, "dll certificate serial number", params.UnicodeString, []string{"dll.signature.serial = '330000023241fb59996dcc4dff000000000232'"}, nil, nil}
	fields[DllSignatureSubject] = FieldInfo{DllSignatureSubject, "dll certificate subject", params.UnicodeString, []string{"dll.signature.subject contains 'Washington, Redmond, Microsoft Corporation'"}, nil, nil}
	fields[DllSignatureIssuer] = FieldInfo{DllSignatureIssuer, "dll certificate CA", params.UnicodeString, []string{"dll.signature.issuer contains 'Washington, Redmond, Microsoft Corporation'"}, nil, nil}
	fields[DllSignatureAfter] = FieldInfo{DllSignatureAfter, "moddllule certificate expiration date", params.Time, []string{"dll.signature.after contains '2024-02-01 00:05:42 +0000 UTC'"}, nil, nil}
	fields[DllSignatureBefore] = FieldInfo{DllSignatureBefore, "dll certificate enrollment date", params.Time, []string{"dll.signature.before contains '2024-02-01 00:05:42 +0000 UTC'"}, nil, nil}
	fields[DllIsDotnet] = FieldInfo{DllIsDotnet, "indicates if the loaded dll is a .NET assembly", params.Bool, []string{"dll.pe.is_dotnet'"}, nil, nil}
	fields[FileObject] = FieldInfo{FileObject, "file object address", params.Uint64, []string{"file.object = 18446738026482168384"}, nil, nil}
	fields[FilePath] = FieldInfo{FilePath, "full file path", params.UnicodeString, []string{"file.path = 'C:\\Windows\\System32'"}, nil, nil}
	fields[FilePathStem] = FieldInfo{FilePathStem, "full file path without extension", params.UnicodeString, []string{"file.path.stem = 'C:\\Windows\\System32\\cmd'"}, nil, nil}
	fields[FileName] = FieldInfo{FileName, "full file name", params.UnicodeString, []string{"file.name contains 'mimikatz'"}, nil, nil}
	fields[FileOperation] = FieldInfo{FileOperation, "file operation", params.AnsiString, []string{"file.operation = 'open'"}, nil, nil}
	fields[FileShareMask] = FieldInfo{FileShareMask, "file share mask", params.AnsiString, []string{"file.share.mask = 'READ'"}, &Deprecation{Since: "3.1.0", Fields: []Field{FileShareMode}}, nil}
	fields[FileShareMode] = FieldInfo{FileShareMask, "file share mode", params.AnsiString, []string{"file.share_mode = 'DENY'"}, nil, nil}
	fields[FileIOSize] = FieldInfo{FileIOSize, "file I/O size", params.Uint32, []string{"file.io.size > 512"}, nil, nil}
	fields[FileOffset] = FieldInfo{FileOffset, "file offset", params.Uint64, []string{"file.offset = 1024"}, nil, nil}
	fields[FileType] = FieldInfo{FileType, "file type", params.AnsiString, []string{"file.type = 'directory'"}, nil, nil}
	fields[FileExtension] = FieldInfo{FileExtension, "file extension", params.AnsiString, []string{"file.extension = '.dll'"}, nil, nil}
	fields[FileAttributes] = FieldInfo{FileAttributes, "file attributes", params.Slice, []string{"file.attributes in ('archive', 'hidden')"}, nil, nil}
	fields[FileStatus] = FieldInfo{FileStatus, "file operation status message", params.UnicodeString, []string{"file.status != 'success'"}, nil, nil}
	fields[FileViewBase] = FieldInfo{FileViewBase, "view base address", params.Address, []string{"file.view.base = '25d42170000'"}, nil, nil}
	fields[FileViewSize] = FieldInfo{FileViewSize, "size of the mapped view", params.Uint64, []string{"file.view.size > 1024"}, nil, nil}
	fields[FileViewType] = FieldInfo{FileViewType, "type of the mapped view section", params.Enum, []string{"file.view.type = 'IMAGE'"}, nil, nil}
	fields[FileViewProtection] = FieldInfo{FileViewProtection, "protection rights of the section view", params.AnsiString, []string{"file.view.protection = 'READONLY'"}, nil, nil}
	fields[FileIsDLL] = FieldInfo{FileIsDLL, "indicates if the created file is a DLL", params.Bool, []string{"file.is_dll'"}, nil, nil}
	fields[FileIsDriver] = FieldInfo{FileIsDriver, "indicates if the created file is a driver", params.Bool, []string{"file.is_driver'"}, nil, nil}
	fields[FileIsExecutable] = FieldInfo{FileIsExecutable, "indicates if the created file is an executable", params.Bool, []string{"file.is_exec'"}, nil, nil}
	fields[FilePID] = FieldInfo{FilePID, "denotes the process id performing file operation", params.PID, []string{"file.pid = 4"}, nil, nil}
	fields[FileKey] = FieldInfo{FileKey, "uniquely identifies the file object", params.Uint64, []string{"file.key = 12446738026482168384"}, nil, nil}
	fields[FileInfoClass] = FieldInfo{FileInfoClass, "identifies the file information class", params.Enum, []string{"file.info_class = 'Allocation'"}, nil, nil}
	fields[FileInfoAllocationSize] = FieldInfo{FileInfoAllocationSize, "file allocation size", params.Uint64, []string{"file.info.allocation_size > 645400"}, nil, nil}
	fields[FileInfoEOFSize] = FieldInfo{FileInfoEOFSize, "file EOF size", params.Uint64, []string{"file.info.eof_size > 1000"}, nil, nil}
	fields[FileInfoIsDispositionDeleteFile] = FieldInfo{FileInfoIsDispositionDeleteFile, "indicates if the file is deleted when its handle is closed", params.Bool, []string{"file.info.is_disposition_file_delete = true"}, nil, nil}
	fields[RegistryPath] = FieldInfo{RegistryPath, "fully qualified registry path", params.UnicodeString, []string{"registry.path = 'HKEY_LOCAL_MACHINE\\SYSTEM'"}, nil, nil}
	fields[RegistryKeyName] = FieldInfo{RegistryKeyName, "registry key name", params.UnicodeString, []string{"registry.key.name = 'CurrentControlSet'"}, nil, nil}
	fields[RegistryKCB] = FieldInfo{RegistryKCB, "registry KCB address", params.Address, []string{"registry.kcb = 'FFFFB905D60C2268'"}, nil, nil}
	fields[RegistryValue] = FieldInfo{RegistryValue, "registry value name", params.UnicodeString, []string{"registry.value = 'Epoch'"}, nil, nil}
	fields[RegistryValueType] = FieldInfo{RegistryValueType, "type of registry value", params.UnicodeString, []string{"registry.value.type = 'REG_SZ'"}, nil, nil}
	fields[RegistryData] = FieldInfo{RegistryData, "registry value captured data", params.Object, []string{"registry.data = '%SystemRoot%'"}, nil, nil}
	fields[RegistryStatus] = FieldInfo{RegistryStatus, "status of registry operation", params.UnicodeString, []string{"registry.status != 'success'"}, nil, nil}
	fields[NetDIP] = FieldInfo{NetDIP, "destination IP address", params.IP, []string{"net.dip = 172.17.0.3"}, nil, nil}
	fields[NetSIP] = FieldInfo{NetSIP, "source IP address", params.IP, []string{"net.sip = 127.0.0.1"}, nil, nil}
	fields[NetDport] = FieldInfo{NetDport, "destination port", params.Uint16, []string{"net.dport in (80, 443, 8080)"}, nil, nil}
	fields[NetSport] = FieldInfo{NetSport, "source port", params.Uint16, []string{"net.sport != 3306"}, nil, nil}
	fields[NetDportName] = FieldInfo{NetDportName, "destination port name", params.AnsiString, []string{"net.dport.name = 'dns'"}, nil, nil}
	fields[NetSportName] = FieldInfo{NetSportName, "source port name", params.AnsiString, []string{"net.sport.name = 'http'"}, nil, nil}
	fields[NetL4Proto] = FieldInfo{NetL4Proto, "layer 4 protocol name", params.AnsiString, []string{"net.l4.proto = 'TCP"}, nil, nil}
	fields[NetPacketSize] = FieldInfo{NetPacketSize, "packet size", params.Uint32, []string{"net.size > 512"}, nil, nil}
	fields[NetSIPNames] = FieldInfo{NetSIPNames, "source IP names", params.Slice, []string{"net.sip.names in ('github.com.')"}, nil, nil}
	fields[NetDIPNames] = FieldInfo{NetDIPNames, "destination IP names", params.Slice, []string{"net.dip.names in ('github.com.')"}, nil, nil}
	fields[PeNumSections] = FieldInfo{PeNumSections, "number of sections", params.Uint16, []string{"pe.nsections < 5"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeNumSections}}, nil}
	fields[PeNumSymbols] = FieldInfo{PeNumSymbols, "number of entries in the symbol table", params.Uint32, []string{"pe.nsymbols > 230"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeNumSymbols}}, nil}
	fields[PeBaseAddress] = FieldInfo{PeBaseAddress, "image base address", params.Address, []string{"pe.address.base = '140000000'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeBaseAddress}}, nil}
	fields[PeEntrypoint] = FieldInfo{PeEntrypoint, "address of the entrypoint function", params.Address, []string{"pe.address.entrypoint = '20110'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeEntrypoint}}, nil}
	fields[PeSymbols] = FieldInfo{PeSymbols, "imported symbols", params.Slice, []string{"pe.symbols in ('GetTextFaceW', 'GetProcessHeap')"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeSymbols}}, nil}
	fields[PeImports] = FieldInfo{PeImports, "imported dynamic linked libraries", params.Slice, []string{"pe.imports in ('msvcrt.dll', 'GDI32.dll'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeImports}}, nil}
	fields[PeResources] = FieldInfo{PeResources, "version resources", params.Map, []string{"pe.resources[FileDescription] = 'Notepad'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeResources}}, &Argument{Optional: true, Pattern: "[a-zA-Z0-9_]+", ValidationFunc: func(s string) bool {
		for _, c := range s {
			switch {
			case unicode.IsLower(c):
			case unicode.IsUpper(c):
			case unicode.IsNumber(c):
			case c == '_':
			default:
				return false
			}
		}
		return true
	}}}
	fields[PeCompany] = FieldInfo{PeCompany, "internal company name of the file provided at compile-time", params.UnicodeString, []string{"pe.company = 'Microsoft Corporation'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeCompany}}, nil}
	fields[PeCopyright] = FieldInfo{PeCopyright, "copyright notice for the file emitted at compile-time", params.UnicodeString, []string{"pe.copyright = '© Microsoft Corporation'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeCopyright}}, nil}
	fields[PeDescription] = FieldInfo{PeDescription, "internal description of the file provided at compile-time", params.UnicodeString, []string{"pe.description = 'Notepad'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeDescription}}, nil}
	fields[PeFileName] = FieldInfo{PeFileName, "original file name supplied at compile-time", params.UnicodeString, []string{"pe.file.name = 'NOTEPAD.EXE'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeFileName}}, nil}
	fields[PeFileVersion] = FieldInfo{PeFileVersion, "file version supplied at compile-time", params.UnicodeString, []string{"pe.file.version = '10.0.18362.693 (WinBuild.160101.0800)'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeFileVersion}}, nil}
	fields[PeProduct] = FieldInfo{PeProduct, "internal product name of the file provided at compile-time", params.UnicodeString, []string{"pe.product = 'Microsoft® Windows® Operating System'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeProduct}}, nil}
	fields[PeProductVersion] = FieldInfo{PeProductVersion, "internal product version of the file provided at compile-time", params.UnicodeString, []string{"pe.product.version = '10.0.18362.693'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeProductVersion}}, nil}
	fields[PeIsDLL] = FieldInfo{PeIsDLL, "indicates if the loaded image or created file is a DLL", params.Bool, []string{"pe.is_dll'"}, &Deprecation{Since: "2.0.0", Fields: []Field{FileIsDLL, ImageIsDLL}}, nil}
	fields[PeIsDriver] = FieldInfo{PeIsDriver, "indicates if the loaded image or created file is a driver", params.Bool, []string{"pe.is_driver'"}, &Deprecation{Since: "2.0.0", Fields: []Field{FileIsDriver, ImageIsDriver}}, nil}
	fields[PeIsExecutable] = FieldInfo{PeIsExecutable, "indicates if the loaded image or created file is an executable", params.Bool, []string{"pe.is_exec'"}, &Deprecation{Since: "2.0.0", Fields: []Field{FileIsExecutable, ImageIsExecutable}}, nil}
	fields[PeImphash] = FieldInfo{PeImphash, "import hash", params.AnsiString, []string{"pe.impash = '5d3861c5c547f8a34e471ba273a732b2'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeImphash}}, nil}
	fields[PeIsDotnet] = FieldInfo{PeIsDotnet, "indicates if PE contains CLR data", params.Bool, []string{"pe.is_dotnet"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeIsDotnet}}, nil}
	fields[PeAnomalies] = FieldInfo{PeAnomalies, "contains PE anomalies detected during parsing", params.Slice, []string{"pe.anomalies in ('number of sections is 0')"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeAnomalies}}, nil}
	fields[PeIsSigned] = FieldInfo{PeIsSigned, "indicates if the PE has embedded or catalog signature", params.Bool, []string{"pe.is_signed"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsSignatureExists}}, nil}
	fields[PeIsTrusted] = FieldInfo{PeIsTrusted, "indicates if the PE certificate chain is trusted", params.Bool, []string{"pe.is_trusted"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsSignatureTrusted}}, nil}
	fields[PeCertSerial] = FieldInfo{PeCertSerial, "PE certificate serial number", params.UnicodeString, []string{"pe.cert.serial = '330000023241fb59996dcc4dff000000000232'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsSignatureSerial}}, nil}
	fields[PeCertSubject] = FieldInfo{PeCertSubject, "PE certificate subject", params.UnicodeString, []string{"pe.cert.subject contains 'Washington, Redmond, Microsoft Corporation'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsSignatureSubject}}, nil}
	fields[PeCertIssuer] = FieldInfo{PeCertIssuer, "PE certificate CA", params.UnicodeString, []string{"pe.cert.issuer contains 'Washington, Redmond, Microsoft Corporation'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsSignatureIssuer}}, nil}
	fields[PeCertAfter] = FieldInfo{PeCertAfter, "PE certificate expiration date", params.Time, []string{"pe.cert.after contains '2024-02-01 00:05:42 +0000 UTC'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsSignatureAfter}}, nil}
	fields[PeCertBefore] = FieldInfo{PeCertBefore, "PE certificate enrollment date", params.Time, []string{"pe.cert.before contains '2024-02-01 00:05:42 +0000 UTC'"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsSignatureBefore}}, nil}
	fields[PeIsModified] = FieldInfo{PeIsModified, "indicates if disk and in-memory PE headers differ", params.Bool, []string{"pe.is_modified"}, &Deprecation{Since: "3.0.0", Fields: []Field{PsPeIsModified}}, nil}
	fields[MemBaseAddress] = FieldInfo{MemBaseAddress, "region base address", params.Address, []string{"mem.address = '211d13f2000'"}, nil, nil}
	fields[MemRegionSize] = FieldInfo{MemRegionSize, "region size", params.Uint64, []string{"mem.size > 438272"}, nil, nil}
	fields[MemAllocType] = FieldInfo{MemAllocType, "region allocation or release type", params.Flags, []string{"mem.alloc = 'COMMIT'"}, nil, nil}
	fields[MemPageType] = FieldInfo{MemPageType, "page type of the allocated region", params.Enum, []string{"mem.type = 'PRIVATE'"}, nil, nil}
	fields[MemProtection] = FieldInfo{MemProtection, "allocated region protection type", params.Enum, []string{"mem.protection = 'READWRITE'"}, nil, nil}
	fields[MemProtectionMask] = FieldInfo{MemProtectionMask, "allocated region protection in mask notation", params.Enum, []string{"mem.protection.mask = 'RWX'"}, nil, nil}
	fields[DNSName] = FieldInfo{DNSName, "dns query name", params.UnicodeString, []string{"dns.name = 'example.org'"}, nil, nil}
	fields[DNSRR] = FieldInfo{DNSRR, "dns resource record type", params.AnsiString, []string{"dns.rr = 'AA'"}, nil, nil}
	fields[DNSOptions] = FieldInfo{DNSOptions, "dns query options", params.Flags64, []string{"dns.options in ('ADDRCONFIG', 'DUAL_ADDR')"}, nil, nil}
	fields[DNSRcode] = FieldInfo{DNSRR, "dns response status", params.AnsiString, []string{"dns.rcode = 'NXDOMAIN'"}, nil, nil}
	fields[DNSAnswers] = FieldInfo{DNSAnswers, "dns response answers", params.Slice, []string{"dns.answers in ('o.lencr.edgesuite.net', 'a1887.dscq.akamai.net')"}, nil, nil}
}
