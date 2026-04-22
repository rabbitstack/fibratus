# Fields

##### In the Fibratus rule language, fields represent structured attributes extracted from process metadata, file paths, registry keys, or callstacks.

Each field evaluates to a specific data type, which determines how it can be compared, which operators are valid, and which functions can be applied. Understanding field types is essential for writing correct and efficient rules. Fields are accessed using `dot` notation, which reflects their hierarchical structure. This hierarchy mirrors the underlying event schema and helps keep rules expressive and readable. Some fields support optional or required arguments, accessed using `bracket` notation, for example, `evt.arg[exe]`

## Supported data types

### String

String values represent textual data such as:

* File paths `file.name` or `file.path`
* Process metadata `ps.name` or `ps.exe`
* Registry keys `registry.path`

Strings must be enclosed in single quotes. Special characters must be escaped. String comparisons are case-sensitive by default. Use case-insensitive operators or normalization [functions](functions.md).

### Number

Numeric fields can be integers or floating-point numbers. Numbers use dot (`.`) notation for decimals.

### Boolean

Boolean fields represent truth values including `true` and `false`. Booleans are commonly used in flags, security attributes and state indicators.

### IP address

IP fields represent `IPv4` addresses. These fields support equality comparisons and range checks depending on operators/functions available.

!> IP values are not strings and they are parsed and compared as structured addresses.

### Collections

Certain filter fields return a sequence of items rather than a primitive value. For example, `ps.modules` returns an array of process DLLs.

## Filter fields

The following tables summarize available field names that can be employed in detection rules.

### Event

| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| `evt.seq` | Monotonic event sequence number       | `evt.seq > 666`   |
| `evt.pid` | Process identifier generating the event       | `evt.pid = 6`   |
| `evt.tid` | Thread identifier generating the event       | `evt.tid = 1024`   |
| `evt.cpu` | Logical processor core where the event was generated       | `evt.cpu = 2`   |
| `evt.name` | Symbolical event name       | `evt.name = 'CreateThread'`   |
| `evt.category` | Category to which the event pertains      | `evt.category = 'registry'`   |
| `evt.desc` | Cursory event description      | `evt.desc contains 'Creates'`   |
| `evt.host` | Hostname on which the event was produced     | `evt.host contains 'dev'`   |
| `evt.nparams` | Number of event parameters     | `evt.nparams > 2`   |
| `evt.time` | Event timestamp as a time string      | `evt.time = '17:05:32'`   |
| `evt.time.h` | Hour within the day on which the event occurred      | `evt.time.h = 23`   |
| `evt.time.m` | Minute offset within the hour on which the event occurred      | `evt.time.m = 54`   |
| `evt.time.s` | Second offset within the minute on which the event occurred      | `evt.time.s = 0`   |
| `evt.time.ns` | Nanoseconds specified by the event timestamp      | `evt.time.ns > 1591191629102337000`   |
| `evt.date` | Event timestamp as a date string      | `evt.date = '2018-03-03'`   |
| `evt.date.d` | Day of the month on which the event occurred      | `evt.date.d = 12`   |
| `evt.date.m` | Month of the year on which the event occurred      | `evt.date.m = 11`   |
| `evt.date.y` | Year on which the event occurred      | `evt.date.y = 2020`   |
| `evt.date.tz` | Time zone associated with the event timestamp     | `evt.date.tz = 'UTC'`   |
| `evt.date.week` | Week number within the year on which the event occurred     | `evt.date.week = 2`   |
| `evt.date.weekday` | Week day on which the event occurred     | `evt.date.weekday = 'Monday'`   |
| `evt.arg[]` | Accesses a specific event parameter via internal name | `evt.arg[exe] = 'C:\\Windows\\cmd.exe'`   |
| `evt.is_direct_syscall` | Indicates if this event is originated by a direct syscall | `evt.is_direct_syscall`   |
| `evt.is_indirect_syscall` | Indicates if this event is originated by an indirect syscall | `evt.is_indirect_syscall`   |

### Process

| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| `ps.pid` | Process identifier generating the event. Alias for `evt.pid` | `ps.pid = 1024`   |
| `ps.ppid` | Parent process identifier of the process generating the event | `ps.ppid = 25`   |
| `ps.name` | Process (image) path name that generates an event | `ps.name = 'cmd.exe'`   |
| `ps.cmdline` | Process command line | `ps.cmdline contains '/E c:\\ads\\file.txt:regfile.reg'`   |
| `ps.exe` | Full name of the process' executable | `ps.exe = 'C:\\Windows\\system32\\cmd.exe'`   |
| `ps.args` | Process command line arguments | `ps.args in ('/cdir', '/-C')`   |
| `ps.cwd` | Process current working directory | `ps.cwd = 'C:\\Users\\Default'`   |
| `ps.sid` | Security identifier under which this process is run | `ps.sid = 'S-1-5-18'`   |
| `ps.domain` | Process domain name  | `ps.domain = 'NT AUTHORITY'`   |
| `ps.username` | Process user name  | `ps.username = 'SYSTEM'`   |
| `ps.sessionid` | Unique identifier for the current session | `ps.sessionid = 1`   |
| `ps.access.mask` | Process access rights | `ps.access.mask = '0x1000'`   |
| `ps.access.mask.names` | Process access human-readable rights | `ps.access.mask.names in ('TERMINATE', 'QUERY_INFORMATION')`   |
| `ps.access.status` | Process access status | `ps.access.status = 'success'`   |
| `ps.envs` | Process environment variables | `ps.envs in ('MOZ_CRASHREPORTER_DATA_DIRECTORY')`  |
| `ps.envs[]` | Accesses a specific environment variable. Prefix matches are supported | `ps.envs['MOZ_CRASHREPORTER'] = 'C:\\Program Files\\Firefox'`  |
| `ps.dtb` | Process directory table base address | `ps.dtb = '7ffe0000'` |
| `ps.handles` | Allocated process handles | `ps.handles in ('\\BaseNamedObjects\\__ComCatalogCache__')`   |
| `ps.handle.types` | Allocated process handle types | `ps.handle.types in ('Key', 'Mutant', 'Section')`   |
| `ps.modules` | Modules loaded by the process | `ps.modules in ('C:\\Windows\\System32\\crypt32.dll')`   |
| `ps.parent.name` | Parent process name  | `ps.parent.name = 'powershell.exe'`   |
| `ps.parent.pid` | Parent process identifier  | `ps.parent.pid = 2340`   |
| `ps.parent.cmdline` | Parent process command line  | `ps.parent.cmdline contains 'attrib'`   |
| `ps.parent.exe` | Full name of the parent process executable  | `ps.parent.exe = 'C:\\Windows\\system32\\cmd.exe'`   |
| `ps.parent.cwd` | Parent process current working directory  | `ps.parent.cwd = 'C:\\Users\\Default'`   |
| `ps.parent.sid` | Security identifier under which the parent process is run  | `ps.parent.sid = 'S-1-5-18'`   |
| `ps.parent.domain` | Parent process domain name  | `ps.parent.domain = 'NT AUTHORITY'`   |
| `ps.parent.username` | Parent process user name  | `ps.parent.username = 'SYSTEM'`   |
| `ps.parent.sessionid` | Unique identifier for the current session of the parent process  | `ps.parent.session = 1`   |
| `ps.parent.dtb` | Parent process directory table base address  | `ps.parent.dtb = 'powershell.exe'`   |
| `ps.parent.envs` | Parent process environment variables   | `ps.parent.envs in ('PROCESSOR_LEVEL')'`   |
| `ps.parent.handles` | Allocated parent process handles  | `ps.parent.handles in ('\\...\\Cor_SxSPublic_IPCBlock')`   |
| `ps.parent.handle.types` | Allocated parent process handles types  | `ps.parent.handle.types in ('Key', 'Mutant', 'Section')`   |
| `ps.ancestor` | Process ancestors  | `ps.ancestor in ('winword.exe', 'powershell.exe')`   |
| `ps.ancestor[]` | Access an ancestor at the specified level  | `ps.ancestor[1] = 'winword.exe'` |
| `ps.is_wow64` | Indicates if the process generating the event is a 32-bit child process is created in 64-bit Windows system | `ps.is_wow64` |
| `ps.is_packaged` | Indicates if the process process generating the event is packaged with the MSIX technology | `ps.is_packaged` |
| `ps.is_protected` | Indicates if the process generating the event is a protected process | `ps.is_protected` |
| `ps.parent.is_wow64` | Indicates if the parent process generating the event is a 32-bit process created in 64-bit Windows system | `ps.parent.is_wow64` |
| `ps.parent.is_packaged` | Indicates if the parent process generating the event is packaged with the MSIX technology | `ps.parent.is_packaged` |
| `ps.parent.is_protected` | Indicates if the parent process generating the event is a protected process | `ps.parent.is_protected` |
| `ps.token.integrity_level` | Process token integrity level | `ps.token.integrity_level = 'HIGH'` |
| `ps.token.elevation_type` | Process token elevation type | `ps.token.elevation_type = 'LIMITED'` |
| `ps.token.is_elevated` | Indicates if the process token is elevated | `ps.token.is_elevated` |
| `ps.parent.token.integrity_level` | Process parent token integrity level | `ps.parent.token.integrity_level = 'HIGH'` |
| `ps.parent.token.elevation_type` | Process parent token elevation type | `ps.parent.token.elevation_type = 'LIMITED'` |
| `ps.parent.token.is_elevated` | Indicates if the parent process token is elevated | `ps.parent.token.is_elevated` |
| `ps.signature.exists` | Indicates if the process executable is signed | `ps.signature.signed`   |
| `ps.signature.trusted` |  Indicates if the process executable is trusted | `ps.signature.trusted`   |
| `ps.signature.serial` | Process executable signature certificate serial number | `ps.signature.serial = '330000023241fb59996dcc4dff000000000232'`   |
| `ps.signature.subject` | Process executable signature certificate subject | `ps.signature.subject contains 'Washington, Redmond, Microsoft Corporation'`   |
| `ps.signature.issuer` | Process executable signature certificate CA | `ps.signature.issuer contains 'US, Washington, Redmond, Microsoft Windows Production PCA 2011'`   |
| `ps.signature.after` | Process executable signature certificate expiration date | `ps.signature.after contains '2024-02-01 00:05:42 +0000 UTC'`   |
| `ps.signature.before` | Process executable signature certificate enrollment date | `ps.signature.before contains '2024-02-01 00:05:42 +0000 UTC'`   |


### Thread

| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| `thread.prio` | Scheduler priority of the thread | `thread.prio = 5`   |
| `thread.io.prio` | I/O priority hint for scheduling I/O operations | `thread.io.prio = 4`   |
| `thread.page.prio` | Memory page priority hint for memory pages accessed by the thread | `thread.page.prio = 12`   |
| `thread.kstack.base` | Base address of the thread's kernel space stack | `thread.kstack.base = 'a65d800000'`   |
| `thread.kstack.limit` | Limit of the thread's kernel space stack | `thread.kstack.limit = 'a85d800000'`   |
| `thread.ustack.base` | Base address of the thread's user space stack | `thread.ustack.base = '7ffe0000'`   |
| `thread.ustack.limit` | Limit of the thread's user space stack | `thread.ustack.limit = '8ffe0000'`   |
| `thread.start_address` | Start address of the function to be executed by the thread | `thread.start_address = '7efe0000'`   |
| `thread.access.mask` | Thread access rights | `thread.access.mask = '0x1800'`   |
| `thread.access.mask.names` | Thread access human-readable rights | `thread.access.mask.names in ('QUERY_LIMITED_INFORMATION')`   |
| `thread.access.status` | Thread access status | `thread.access.status = 'Success'`   |
| `thread.teb_address` | The base address of the thread environment block | `thread.teb_address = '8f30893000'`   |
| `thread.start_address.symbol` | Thread start address symbol | `thread.start_address.symbol = 'LoadImage'`   |
| `thread.start_address.module` | Thread start address module | `thread.start_address.module endswith 'kernel32.dll'`   |


### Threadpool

| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| `threadpool.id` | Thread pool identifier | `threadpool.id = '20f5fc02440'`   |
| `threadpool.task.id` | Thread pool task identifier | `threadpool.task.id = '20f7ecd21f8'`   |
| `threadpool.callback.address` | Thread pool callback address | `threadpool.callback.address = '7ff868739ed0'` |
| `threadpool.callback.symbol` | Thread pool callback address symbol | `threadpool.callback.symbol = 'RtlDestroyQueryDebugBuffer'`   |
| `threadpool.callback.module` | Thread pool callback address module | `threadpool.callback.module contains 'ntdll.dll'`   |
| `threadpool.callback.context` | Thread pool callback context address | `threadpool.callback.context = '1df41e07bd0'`   |
| `threadpool.callback.context.rip` | Thread pool callback thread context instruction pointer | `threadpool.callback.context.rip = '1df42ffc1f8'`   |
| `threadpool.callback.context.rip.symbol` | Thread pool callback thread context instruction pointer symbol | `threadpool.callback.context.rip.symbol = 'VirtualProtect'`   |
| `threadpool.callback.context.rip.module` | Thread pool callback thread context instruction pointer module | `threadpool.callback.context.rip.module contains 'ntdll.dll'`   |
| `threadpool.subprocess_tag` | Thread pool service identifier | `threadpool.subprocess_tag = '10d'`   |
| `threadpool.timer.duetime` | Thread pool timer due time | `threadpool.timer.duetime > 10`   |
| `threadpool.timer.subqueue` | Thread pool timer subqueue address | `threadpool.timer.subqueue = '1db401703e8'`   |
| `threadpool.timer.address` | Thread pool timer address | `threadpool.timer.address = '3e8'`   |
| `threadpool.timer.period` | Thread pool timer period | `threadpool.timer.period = 0`   |
| `threadpool.timer.window` | Thread pool timer tolerate period | `threadpool.timer.window = 0`   |
| `threadpool.timer.is_absolute` | Indicates if the thread pool timer is absolute or relative | `threadpool.timer.is_absolute = true`   |


### Callstack

| Field Name  | Description | Example     |
| :---        |    :----   |   :--- |
| `thread.callstack.summary` | Callstack summary showing involved modules | `thread.callstack.summary contains 'ntdll.dll\|KERNELBASE.dll'` |
| `thread.callstack.detail` | Detailed information of each stack frame | `thread.callstack.detail contains 'KERNELBASE.dll!CreateProcessW'` |
| `thread.callstack.modules` | List of modules comprising the callstack | `thread.callstack.modules in ('C:\WINDOWS\System32\KERNELBASE.dll')` |
| `thread.callstack.symbols` | List of symbols comprising the callstack | `thread.callstack.symbols in ('ntdll.dll!NtCreateProcess')` |
| `thread.callstack.allocation_sizes` | Allocation sizes of private pages | `thread.callstack.allocation_sizes > 10000` |
| `thread.callstack.protections` | Page protections masks of each frame | `thread.callstack.protections in ('RWX', 'WX')'` |
| `thread.callstack.callsite_leading_assembly` | Callsite leading assembly instructions | `thread.callstack.callsite_leading_assembly in ('mov r10,rcx', 'syscall')` |
| `thread.callstack.callsite_trailing_assembly` | Callsite trailing assembly instructions | `thread.callstack.callsite_trailing_assembly in ('add esp, 0xab')` |
| `thread.callstack.is_unbacked` | Indicates if the callstack contains unbacked regions | `thread.callstack.is_unbacked` |
| `thread.callstack.addresses` | List of all callstack return addresses | `thread.callstack.addresses in ('7ffb5c1d0396')` |
| `thread.callstack.final_user_module.name` | The final user module name | `thread.callstack.final_user_module.name != 'ntdll.dll'` |
| `thread.callstack.final_user_module.path` | The final user module path | `thread.callstack.final_user_module.path imatches '?:\\Windows\\System32\\ntdll.dll'` |
| `thread.callstack.final_user_symbol.name` | The final user symbol name | `thread.callstack.final_user_symbol.name imatches 'CreateProcess*'` |
| `thread.callstack.final_kernel_module.name` | The final kernel module name | `thread.callstack.final_kernel_module.name = 'FLTMGR.SYS'` |
| `thread.callstack.final_kernel_module.path` | The final kernel module path | `thread.callstack.final_kernel_module.path imatches '?:\\WINDOWS\\System32\\drivers\\FLTMGR.SYS'` |
| `thread.callstack.final_kernel_symbol.name` | The final kernel symbol name | `thread.callstack.final_kernel_symbol.name = 'FltGetStreamContext'` |
| `thread.callstack.final_user_module.signature.is_signed` | Indicates if the final user module is signed | `thread.callstack.final_user_module.signature.is_signed = true` |
| `thread.callstack.final_user_module.signature.is_trusted` | Indicates if the final user module signature is trusted | `thread.callstack.final_user_module.signature.is_trusted = true` |
| `thread.callstack.final_user_module.signature.cert.issuer` | The final user module signature certificate issuer | `thread.callstack.final_user_module.signature.cert.issuer imatches '*Microsoft Corporation*'` |
| `thread.callstack.final_user_module.signature.cert.subject` |  The final user module signature certificate subject | `thread.callstack.final_user_module.signature.cert.subject imatches '*Microsoft Windows*'` |

### Module

| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| `module.path` | Full module path | `module.path = 'C:\\Windows\\System32\\advapi32.dll'`   |
| `module.path.stem` | Module path without extension | `module.path.stem = 'C:\\Windows\\System32\\advapi32'`   |
| `module.name` | Module name | `module.name = 'advapi32.dll'`   |
| `module.base` | Base address of the process in which the module is loaded | `module.base = 'a65d800000'`   |
| `module.checksum` | Module checksum | `module.checksum = 746424`   |
| `module.size` | Module VA size | `module.size > 1024`   |
| `module.default_address` | Default module address | `module.default_address = '7efe0000'`   |
| `module.signature.type` | Module signature type | `module.signature.type != 'NONE'`   |
| `module.signature.level` | Module signature level | `module.signature.level = 'AUTHENTICODE'`   |
| `module.signature.exists` | Indicates if module signature exists | `module.signature.exists` |
| `module.signature.trusted` | Indicates if module signature is trusted | `module.signature.trusted` |
| `module.signature.serial` | Module certificate serial number | `module.signature.serial = '330000023241fb59996dcc4dff000000000232'`   |
| `module.signature.subject` | Module certificate subject | `module.signature.subject contains 'Washington, Redmond, Microsoft Corporation'`   |
| `module.signature.issuer` | Module certificate CA | `module.signature.issuer contains 'US, Washington, Redmond, Microsoft Windows Production PCA 2011`   |
| `imodule.signature.after` | Module certificate expiration date | `module.signature.after contains '2024-02-01 00:05:42 +0000 UTC'`   |
| `module.signature.before` | Module certificate enrollment date | `module.signature.before contains '2024-02-01 00:05:42 +0000 UTC'`   |
| `image.is_driver_malicious` | Indicates if the loaded driver is malicious | `module.is_driver_malicious`  |
| `image.is_driver_vulnerable` | Indicates if the loaded driver is vulnerable | `module.is_driver_vulnerable` |
| `module.is_dll` | Indicates if the loaded module is a DLL | `module.is_dll` |
| `module.is_driver` | Indicates if the loaded module is a driver | `module.is_driver` |
| `module.is_exec` | Indicates if the loaded module is an executable | `module.is_exec` |
| `module.pe.is_dotnet` | Indicates if the loaded module is a .NET assembly | `module.pe.is_dotnet` |
| `dll.path` | Same as `module.path` but for DLL modules | `dll.path = 'C:\\Windows\\System32\\advapi32.dll'`   |
| `dll.path.stem` | Same as `module.path.stem` but for DLL modules | `dll.path.stem = 'C:\\Windows\\System32\\advapi32'`   |
| `dll.name` | Same as `module.name` but for DLL modules| `dll.name = 'advapi32.dll'`   |
| `dll.base` | Same as `module.base` but for DLL modules | `dll.base = 'a65d800000'`   |
| `dll.size` | Same as `module.size` but for DLL modules | `dll.size > 1024`   |
| `dll.signature.type` | Same as `module.signature.type` but for DLL modules | `dll.signature.type != 'NONE'`   |
| `dll.signature.level` | Same as `module.signature.level` but for DLL modules | `dll.signature.level = 'AUTHENTICODE'`   |
| `dll.signature.exists` | Same as `module.signature.exists` but for DLL modules | `dll.signature.exists` |
| `dll.signature.trusted` | Same as `module.signature.trusted` but for DLL modules | `dll.signature.trusted` |
| `dll.signature.serial` | Same as `module.signature.serial` but for DLL modules | `dll.signature.serial = '330000023241fb59996dcc4dff000000000232'`   |
| `dll.signature.subject` |Same as `module.signature.subject` but for DLL modules| `dll.signature.subject contains 'Washington, Redmond, Microsoft Corporation'`   |
| `dll.signature.issuer` | Same as `module.signature.issuer` but for DLL modules | `dll.signature.issuer contains 'US, Washington, Redmond, Microsoft Windows Production PCA 2011`   |
| `dll.signature.after` | Same as `module.signature.after` but for DLL modules | `dll.signature.after contains '2024-02-01 00:05:42 +0000 UTC'`   |
| `dll.signature.before` | Same as `module.signature.before` but for DLL modules | `dll.signature.before contains '2024-02-01 00:05:42 +0000 UTC'`   |
| `dll.pe.is_dotnet` | Same as `module.pe.is_dotnet` but for DLL modules | `dll.pe.is_dotnet` |


### File

| Field Name  | Description | Example     |
| :---        |    :----   |  :--- |
| `file.object` | File object address in the kernel space | `file.object = 18446738026482168384`   |
| `file.path` | Full file path | `file.path = 'C:\\Windows\\Sytem32\\regedit.exe'`   |
| `file.path.stem` | File path without extension | `file.path.stem = 'C:\\Windows\\Sytem32\\regedit'`   |
| `file.name` | File name | `file.name = 'regedit.exe'`   |
| `file.operation` | Operation performed on the file or I/O device | `file.operation = 'OPEN'`   |
| `file.share.mask` | File share mask | `file.share.mask = 'READ'`   |
| `file.io.size` | I/O read/write size | `file.io.size > 512`   |
| `file.offset` | Read/write position in the file | `file.offset = 1024`   |
| `file.type` | File type. Possible values are `File`, `Directory`, `Pipe`, `Console`, `Mailslot`, `Other`, `Unknown` | `file.type = 'Directory'`   |
| `file.extension` | File extension represents the file extension (e.g. .exe or .dll) | `file.extension = '.dll'`   |
| `file.attributes` | List of file attributes | `file.attributes in ('HIDDEN', 'TEMPORARY')`   |
| `file.status` | System status message of the `CreateFile` operation | `file.status = 'Success'`   |
| `file.view.base` | Base address of the mapped/unmapped section view | `file.view.base = '25d42170000'`   |
| `file.view.size` | Size of the mapped/unmapped section view | `file.view.size > 1024`   |
| `file.view.type` | Type of the mapped/unmapped section view | `file.view.type = 'IMAGE'`   |
| `file.view.protection` | Protection rights of the section view | `file.view.protection = 'READONLY'` |
| `file.is_driver_malicious` | Indicates if the dropped driver is malicious | `file.is_driver_malicious`  |
| `file.is_driver_vulnerable` | Indicates if the dropped driver is vulnerable | `file.is_driver_vulnerable` |
| `file.is_dll` | Indicates if the created file is a DLL | `file.is_dll` |
| `file.is_driver` | Indicates if the created file is a driver | `file.is_driver` |
| `file.is_exec` | Indicates if the created file is an executable | `file.is_exec` |
| `file.info_class` | Identifies the file information class | `file.info_class = 'Allocation'` |
| `file.info.allocation_size` | Represents the file allocation size set via `NtSetInformationFile` syscall | `file.info.allocation_size > 645400` |
| `file.info.eof_size` | Represents the file EOF size set via `NtSetInformationFile` syscall | `file.info.eof_size > 1000` |
| `file.info.is_disposition_file_delete` | Indicates if the file is deleted when its handle is closed | `file.info.is_disposition_file_delete = true` |


### Registry

| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| `registry.path` | Fully qualified registry path | `registry.path = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services'`   |
| `registry.key.name` | Registry key name | `registry.key.name = 'Services'`   |
| `registry.key.handle` | Registry key object address | `registry.key.handle = 'FFFFB905D60C2268'`   |
| `registry.value` | Registry value name | `registry.value = 'Version'` |
| `registry.value.type` | Registry value type | `registry.value.type = 'REG_SZ'` |
| `registry.data` | Registry value data | `registry.data = '%windir%\system32\rundll32.exe'` |
| `registry.status` | Registry operation status | `registry.status != 'Success'` |

### Network

| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| `net.dip` | Destination IP address | `net.dip = 172.17.0.3`   |
| `net.sip` | Source IP address | `net.sip = 127.0.0.1`   |
| `net.dport` | Destination port | `net.dport in (80, 443, 8080)`   |
| `net.sport` | Source port | `net.sport != 3306`   |
| `net.dport.name` | Destination port name as per [IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt) port to service assignation | `net.dport.name = 'dns'`   |
| `net.sport.name` | Source port name as per [IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt) port to service assignation | `net.sport.name = 'http'`   |
| `net.l4.proto` | Layer 4 protocol name | `net.l4.proto = 'TCP'`   |
| `net.size` | Network packet size | `net.size > 512`   |
| `net.dip.names` | List of destination IP address domain names | `net.dip.names in ('github.com.')` |
| `net.sip.names` | List of source IP address domain names | `net.sip.names in ('github.com.')` |


### Handle

| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| `handle.id` | Handle identifier | `handle.id = 24`   |
| `handle.object` | Handle kernel object address | `handle.object = 'FFFFB905DBF61988'`   |
| `handle.name` | Handle name | `handle.name = '\\Device\\NamedPipe\\chrome.12644.28.105826381'`   |
| `handle.type` | Handle type | `handle.type = 'Mutant'`   |


### Memory

| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| `mem.address` | Base address of the allocated region | `mem.address = '211d13f2000'`   |
| `mem.size` | Size of the allocated region | `mem.size > 438272`   |
| `mem.alloc` | Region allocation or release type | `mem.alloc = 'COMMIT'`   |
| `mem.type` | Designates the page type of the allocated region | `mem.type = 'PRIVATE'`   |
| `mem.protection` | Designates the protection type of the allocated region | `mem.protection = 'READWRITE'`   |
| `mem.protection.mask` | Designates the allocated region protection in mask notation | `mem.protection.mask = 'RWX'`   |


### DNS

| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| `dns.name` | DNS query name | `dns.name = 'example.org'`   |
| `dns.rr` | DNS resource record type | `dns.rr = 'AA'`   |
| `dns.options` | DNS query options | `dns.options in ('ADDRCONFIG', 'DUAL_ADDR')`   |
| `dns.rcode` | DNS response status | `dns.rcode = 'NXDOMAIN'`   |
| `dns.answers` | DNS response answers | `dns.answers in ('o.lencr.edgesuite.net', 'a1887.dscq.akamai.net')`   |


### PE

| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| `ps.pe.nsections` | Number of sections | `ps.pe.nsections < 5`   |
| `ps.pe.nsymbols` | Number of entries in the symbol table | `ps.pe.nsymbols > 230`   |
| `ps.pe.address.base` | Image base address | `ps.pe.address.base = '140000000'`   |
| `ps.pe.address.entrypoint` | Address of the entrypoint function | `pe.address.entrypoint = '20110'`   |
| `ps.pe.symbols` | Imported symbols | `ps.pe.symbols in ('GetTextFaceW', 'GetProcessHeap')`   |
| `ps.pe.imports` | Imported dynamic linked libraries | `ps.pe.imports in ('msvcrt.dll', 'GDI32.dll')`   |
| `ps.pe.imphash` | Import hash | `ps.pe.impash = '5d3861c5c547f8a34e471ba273a732b2'`   |
| `ps.pe.resources` | Version and other PE resources | `ps.pe.resources[FileDescription] = 'Notepad'`   |
| `ps.pe.company` | Internal company name of the file provided at compile-time | `ps.pe.company = 'Microsoft Corporation'`  |
| `ps.pe.copyright` | Copyright notice for the file emitted at compile-time | `ps.pe.company = '© Microsoft Corporation'`  |
| `ps.pe.description` | Internal description of the file provided at compile-time | `ps.pe.description = 'Notepad'`   |
| `ps.pe.file.name` | Original file name supplied at compile-time | `ps.pe.file.name = 'NOTEPAD.EXE'`   |
| `ps.pe.file.version` | File version supplied at compile-time | `ps.pe.file.version = '10.0.18362.693 (WinBuild.160101.0800)'`   |
| `ps.pe.product` | Internal product name of the file provided at compile-time | `ps.pe.product = 'Microsoft® Windows® Operating System'`   |
| `ps.pe.product.name` | Internal product version of the file provided at compile-time | `ps.pe.product.version = '10.0.18362.693'`   |
| `ps.pe.is_dotnet` | Indicates if the PE contains CLR (Common Language Runtime) data | `ps.pe.is_dotnet`   |
| `ps.pe.is_modified` | Indicates if on-disk and in-memory PE headers differ | `ps.pe.is_modified'`   |
| `ps.pe.anomalies` | Contains PE anomalies detected during parsing | `ps.pe.anomalies in ('number of sections is 0')`   |
