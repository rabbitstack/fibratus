# Fields

In Fibratus filter expression language the fields can evaluate to one of the following types:

- **string** values are enclosed in single quotes and escaped according to these [rules](filters/filtering?id=escaping-characters)
- **number** field types can be both integer and floating-point numbers. Floating point numbers use the dot notation (`6.54`).
- **IP address** field types represent IPv4 addresses (`172.14.4.4`)
- **bool** represents the `true` or `false` boolean values

## Filter fields {docsify-ignore}

The following tables summarize available field names that can be used in filter expressions.

### Event
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| kevt.seq      | Monotonic event sequence number       | `kevt.seq > 666`   |
| kevt.pid      | Process identifier generating the event       | `kevt.pid = 6`   |
| kevt.tid      | Thread identifier generating the event       | `kevt.tid = 1024`   |
| kevt.cpu      | Logical processor core where the event was generated       | `kevt.cpu = 2`   |
| kevt.name      | Symbolical event name       | `kevt.name = 'CreateThread'`   |
| kevt.category      | Category to which the event pertains      | `kevt.category = 'registry'`   |
| kevt.desc      | Cursory event description      | `kevt.desc contains 'Creates'`   |
| kevt.host      | Hostname on which the event was produced     | `kevt.host contains 'dev'`   |
| kevt.nparams    | Number of event parameters     | `kevt.nparams > 2`   |
| kevt.time      | Event timestamp as a time string      | `kevt.time = '17:05:32'`   |
| kevt.time.h      | Hour within the day on which the event occurred      | `kevt.time.h = 23`   |
| kevt.time.m      | Minute offset within the hour on which the event occurred      | `kevt.time.m = 54`   |
| kevt.time.s      | Second offset within the minute on which the event occurred      | `kevt.time.s = 0`   |
| kevt.time.ns     | Nanoseconds specified by the event timestamp      | `kevt.time.ns > 1591191629102337000`   |
| kevt.date       | Event timestamp as a date string      | `kevt.date = '2018-03-03'`   |
| kevt.date.d     | Day of the month on which the event occurred      | `kevt.date.d = 12`   |
| kevt.date.m     | Month of the year on which the event occurred      | `kevt.date.m = 11`   |
| kevt.date.y     | Year on which the event occurred      | `kevt.date.y = 2020`   |
| kevt.date.tz    | Time zone associated with the event timestamp     | `kevt.date.tz = 'UTC'`   |
| kevt.date.week    | Week number within the year on which the event occurred     | `kevt.date.week = 2`   |
| kevt.date.weekday    | Week day on which the event occurred     | `kevt.date.weekday = 'Monday'`   |
| kevt.arg[]    | Accesses a specific event parameter via internal name | `kevt.arg[exe] = 'C:\\Windows\\cmd.exe'`   |


### Process
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| ps.pid         | Process identifier generating the event. Alias for `kevt.pid` | `ps.pid = 1024`   |
| ps.ppid         | Parent process identifier of the process generating the event | `ps.ppid = 25`   |
| ps.name         | Process (image) path name that generates an event | `ps.name = 'cmd.exe'`   |
| ps.cmdline      | Process command line | `ps.cmdline contains '/E c:\\ads\\file.txt:regfile.reg'`   |
| ps.exe          | Full name of the process' executable | `ps.exe = 'C:\\Windows\\system32\\cmd.exe'`   |
| ps.args         | Process command line arguments | `ps.args in ('/cdir', '/-C')`   |
| ps.cwd          | Process current working directory | `ps.cwd = 'C:\\Users\\Default'`   |
| ps.sid          | Security identifier under which this process is run | `ps.sid = 'S-1-5-18'`   |
| ps.domain       | Process domain name  | `ps.domain = 'NT AUTHORITY'`   |
| ps.username     | Process user name  | `ps.username = 'SYSTEM'`   |
| ps.sessionid    | Unique identifier for the current session | `ps.sessionid = 1`   |
| ps.access.mask  | Process access rights | `ps.access.mask = '0x1000'`   |
| ps.access.mask.names  | Process access human-readable rights | `ps.access.mask.names in ('TERMINATE', 'QUERY_INFORMATION')`   |
| ps.access.status  | Process access status | `ps.access.status = 'success'`   |
| ps.envs         | Process environment variables | `ps.envs in ('MOZ_CRASHREPORTER_DATA_DIRECTORY')`  |
| ps.envs[]       | Accesses a specific environment variable. Prefix matches are supported | `ps.envs['MOZ_CRASHREPORTER'] = 'C:\\Program Files\\Firefox'`  |
| ps.dtb          | Process directory table base address | `ps.dtb = '7ffe0000'` |
| ps.handles      | Allocated process handles | `ps.handles in ('\\BaseNamedObjects\\__ComCatalogCache__')`   |
| ps.handle.types | Allocated process handle types | `ps.handle.types in ('Key', 'Mutant', 'Section')`   |
| ps.modules      | Modules loaded by the process | `ps.modules in ('crypt32.dll', 'xul.dll')`   |
| ps.modules[]    | Accesses a specific process module. Prefix matches are supported  | `ps.modules['crypt'].size > 1024`   |
| ps.parent.name    | Parent process name  | `ps.parent.name = 'powershell.exe'`   |
| ps.parent.pid    | Parent process identifier  | `ps.parent.pid = 2340`   |
| ps.parent.cmdline| Parent process command line  | `ps.parent.cmdline contains 'attrib'`   |
| ps.parent.exe    | Full name of the parent process executable  | `ps.parent.exe = 'C:\\Windows\\system32\\cmd.exe'`   |
| ps.parent.cwd    | Parent process current working directory  | `ps.parent.cwd = 'C:\\Users\\Default'`   |
| ps.parent.sid    | Security identifier under which the parent process is run  | `ps.parent.sid = 'S-1-5-18'`   |
| ps.parent.domain    | Parent process domain name  | `ps.parent.domain = 'NT AUTHORITY'`   |
| ps.parent.username  | Parent process user name  | `ps.parent.username = 'SYSTEM'`   |
| ps.parent.sessionid    | Unique identifier for the current session of the parent process  | `ps.parent.session = 1`   |
| ps.parent.dtb    | Parent process directory table base address  | `ps.parent.dtb = 'powershell.exe'`   |
| ps.parent.envs    | Parent process environment variables   | `ps.parent.envs in ('PROCESSOR_LEVEL')'`   |
| ps.parent.handles    | Allocated parent process handles  | `ps.parent.handles in ('\\...\\Cor_SxSPublic_IPCBlock')`   |
| ps.parent.handle.types    | Allocated parent process handles types  | `ps.parent.handle.types in ('Key', 'Mutant', 'Section')`   |
| ps.ancestor[]    | Process ancestry traversing  | `ps.ancestor[2].name in ('winword.exe', 'powershell.exe')`   |
| ps.child.name    | Child process name  | `ps.child.name = 'cmd.exe'`   |
| ps.child.pid     | Child process identifier  | `ps.child.id = 6050`   |
| ps.child.cmdline    | Child process command line  | `ps.child.cmdline contains '/k /v'`   |
| ps.child.exe     | Child process executable full path  | `ps.child.exe = 'C:\\Windows\\system32\\cmd.exe'`   |
| ps.child.args    | Child process command line arguments  | `ps.child.args in ('C:\\Windows\\system32\\cmd.exe')`   |
| ps.child.sid     | Child process security identifier  | `ps.child.sid = 'S-1-5-20'`   |
| ps.child.sessionid   | Child process session identifier  | `ps.child.sessionid = 1`   |
| ps.child.domain    | Child process domain name  | `ps.child.domain = 'NT AUTHORITY'`   |
| ps.child.username  | Child process user name  | `ps.child.username = 'SYSTEM'`   |
| ps.uuid  | Unique process identifier resistant to repetition | `ps.uuid > 10000400`   |
| ps.parent.uuid  | Unique parent process identifier resistant to repetition  | `ps.parent.uuid = 1843450000440`   |
| ps.child.uuid  | Unique child process identifier resistant to repetition  | `ps.child.uuid > 20030000000`   |


### Thread
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| thread.prio     | Scheduler priority of the thread | `thread.prio = 5`   |
| thread.io.prio  | I/O priority hint for scheduling I/O operations | `thread.io.prio = 4`   |
| thread.page.prio | Memory page priority hint for memory pages accessed by the thread | `thread.page.prio = 12`   |
| thread.kstack.base | Base address of the thread's kernel space stack | `thread.kstack.base = 'a65d800000'`   |
| thread.kstack.limit | Limit of the thread's kernel space stack | `thread.kstack.limit = 'a85d800000'`   |
| thread.ustack.base | Base address of the thread's user space stack | `thread.ustack.base = '7ffe0000'`   |
| thread.ustack.limit | Limit of the thread's user space stack | `thread.ustack.limit = '8ffe0000'`   |
| thread.entrypoint | Starting address of the function to be executed by the thread | `thread.entrypoint = '7efe0000'`   |
| thread.access.mask | Thread access rights | `thread.access.mask = '0x1800'`   |
| thread.access.mask.names | Thread access human-readable rights | `thread.access.mask.names in ('QUERY_LIMITED_INFORMATION')`   |
| thread.access.status | Thread access status | `thread.access.status = 'Success'`   |


### Callstack
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| thread.callstack.summary     | Callstack summary showing involved modules | `thread.callstack.summary contains 'ntdll.dll\|KERNELBASE.dll'` |
| thread.callstack.detail      | Detailed information of each stack frame | `thread.callstack.detail contains 'KERNELBASE.dll!CreateProcessW'` |
| thread.callstack.modules     | List of modules comprising the callstack | `thread.callstack.modules in ('C:\WINDOWS\System32\KERNELBASE.dll')` |
| thread.callstack.symbols     | List of symbols comprising the callstack | `thread.callstack.symbols in ('ntdll.dll!NtCreateProcess')` |
| thread.callstack.allocation_sizes | Allocation sizes of private pages | `thread.callstack.allocation_sizes > 10000` |
| thread.callstack.protections    | Page protections masks of each frame | `thread.callstack.protections in ('RWX', 'WX')'` |
| thread.callstack.callsite_leading_assembly    | Callsite leading assembly instructions | `thread.callstack.callsite_leading_assembly in ('mov r10,rcx', 'syscall')` |
| thread.callstack.callsite_trailing_assembly    | Callsite trailing assembly instructions | `thread.callstack.callsite_trailing_assembly in ('add esp, 0xab')` |
| thread.callstack.is_unbacked    | Indicates if the callstack contains unbacked regions | `thread.callstack.is_unbacked` |


### Image
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| image.name     | Full image path | `image.name = 'C:\\Windows\\System32\\advapi32.dll'`   |
| image.base.address  | Base address of the process in which the image is loaded | `image.base.address = 'a65d800000'`   |
| image.checksum  | Image checksum | `image.checksum = 746424`   |
| image.size  | Image size | `image.size > 1024`   |
| image.default.address  | Default image address | `image.default.address = '7efe0000'`   |
| image.signature.type  | Image signature type | `image.signature.type != 'NONE'`   |
| image.signature.level  | Image signature level | `image.signature.level = 'AUTHENTICODE'`   |
| image.cert.serial  | Image certificate serial number | `image.cert.serial = '330000023241fb59996dcc4dff000000000232'`   |
| image.cert.subject  | Image certificate subject | `image.cert.subject contains 'Washington, Redmond, Microsoft Corporation'`   |
| image.cert.issuer  | Image certificate CA | `image.cert.issuer contains 'US, Washington, Redmond, Microsoft Windows Production PCA 2011`   |
| image.cert.after  | Image certificate expiration date | `image.cert.after contains '2024-02-01 00:05:42 +0000 UTC'`   |
| image.cert.before  | Image certificate enrollment date | `image.cert.before contains '2024-02-01 00:05:42 +0000 UTC'`   |
| image.is_driver_malicious  | Indicates if the loaded driver is malicious | `image.is_driver_malicious`  |
| image.is_driver_vulnerable | Indicates if the loaded driver is vulnerable | `image.is_driver_vulnerable` |
| image.is_dll | Indicates if the loaded image is a DLL | `image.is_dll` |
| image.is_driver | Indicates if the loaded image is a driver | `image.is_driver` |
| image.is_exec | Indicates if the loaded image is an executable | `image.is_exec` |

### File
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| file.object     | File object address in the kernel space | `file.object = 18446738026482168384`   |
| file.name       | Full file name | `file.name = 'C:\\Windows\\Sytem32\\regedit.exe'`   |
| file.operation  | Operation performed on the file or I/O device | `file.operation = 'OPEN'`   |
| file.share.mask | File share mask | `file.share.mask = 'READ'`   |
| file.io.size    | I/O read/write size | `file.io.size > 512`   |
| file.offset     | Read/write position in the file | `file.offset = 1024`   |
| file.type       | File type. Possible values are `File`, `Directory`, `Pipe`, `Console`, `Mailslot`, `Other`, `Unknown` | `file.type = 'Directory'`   |
| file.extension  | File extension represents the file extension (e.g. .exe or .dll) | `file.extension = '.dll'`   |
| file.attributes | List of file attributes | `file.attributes in ('HIDDEN', 'TEMPORARY')`   |
| file.status | System status message of the `CreateFile` operation | `file.status = 'Success'`   |
| file.view.base | Base address of the mapped/unmapped section view | `file.view.base = '25d42170000'`   |
| file.view.size | Size of the mapped/unmapped section view | `file.view.size > 1024`   |
| file.view.type | Type of the mapped/unmapped section view | `file.view.type = 'IMAGE'`   |
| file.view.protection | Protection rights of the section view | `file.view.protection = 'READONLY'` |
| file.is_driver_malicious  | Indicates if the dropped driver is malicious | `file.is_driver_malicious`  |
| file.is_driver_vulnerable | Indicates if the dropped driver is vulnerable | `file.is_driver_vulnerable` |
| file.is_dll | Indicates if the created file is a DLL | `file.is_dll` |
| file.is_driver | Indicates if the created file is a driver | `file.is_driver` |
| file.is_exec | Indicates if the crated file is an executable | `file.is_exec` |


### Registry
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| registry.key.name   | Fully qualified key name | `registry.key.name = 'HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services'`   |
| registry.key.handle | Registry key object address | `registry.key.handle = 'FFFFB905D60C2268'`   |
| registry.value      | Registry value content | `registry.value = '%SystemRoot%\\system32'`   |
| registry.value.type | Registry value type | `registry.value.type = 'REG_SZ'`   |
| registry.status     | Registry operation status | `registry.status != 'Success'`   |

### Network
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| net.dip   | Destination IP address | `net.dip = 172.17.0.3`   |
| net.sip   | Source IP address | `net.sip = 127.0.0.1`   |
| net.dport   | Destination port | `net.dport in (80, 443, 8080)`   |
| net.sport   |Source port | `net.sport != 3306`   |
| net.dport.name   | Destination port name as per [IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt) port to service assignation | `net.dport.name = 'dns'`   |
| net.sport.name   | Source port name as per [IANA](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt) port to service assignation | `net.sport.name = 'http'`   |
| net.l4.proto   | Layer 4 protocol name | `net.l4.proto = 'TCP'`   |
| net.size   | Network packet size | `net.size > 512`   |
| net.dip.names | List of destination IP address domain names | `net.dip.names in ('github.com.')` |
| net.sip.names | List of source IP address domain names | `net.sip.names in ('github.com.')` |


### Handle
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| handle.id   	| Handle identifier | `handle.id = 24`   |
| handle.object | Handle kernel object address | `handle.object = 'FFFFB905DBF61988'`   |
| handle.name   | Handle name | `handle.name = '\\Device\\NamedPipe\\chrome.12644.28.105826381'`   |
| handle.type   | Handle type | `handle.type = 'Mutant'`   |


### Memory
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| mem.address   	| Base address of the allocated region | `mem.address = '211d13f2000'`   |
| mem.size   	| Size of the allocated region | `mem.size > 438272`   |
| mem.alloc   	| Region allocation or release type | `mem.alloc = 'COMMIT'`   |
| mem.type   	| Designates the page type of the allocated region | `mem.type = 'PRIVATE'`   |
| mem.protection   	| Designates the protection type of the allocated region | `mem.protection = 'READWRITE'`   |
| mem.protection.mask   	| Designates the allocated region protection in mask notation | `mem.protection.mask = 'RWX'`   |


### DNS
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| dns.name 	| DNS query name | `dns.name = 'example.org'`   |
| dns.rr 	| DNS resource record type | `dns.rr = 'AA'`   |
| dns.options 	| DNS query options | `dns.options in ('ADDRCONFIG', 'DUAL_ADDR')`   |
| dns.rcode 	| DNS response status | `dns.rcode = 'NXDOMAIN'`   |
| dns.answers 	| DNS response answers | `dns.answers in ('o.lencr.edgesuite.net', 'a1887.dscq.akamai.net')`   |


### PE
| Field Name  | Description | Example     |
| :---        |    :----   |          :---: |
| pe.nsections   | Number of sections | `pe.nsections < 5`   |
| pe.nsymbols   | Number of entries in the symbol table | `pe.nsymbols > 230`   |
| pe.address.base   | Image base address | `pe.address.base = '140000000'`   |
| pe.address.entrypoint   | Address of the entrypoint function | `pe.address.entrypoint = '20110'`   |
| pe.sections[].entropy   | Specified section entropy | `pe.sections[.text].entropy > 6.2`   |
| pe.sections[].size   | Size in bytes of the specified section | `pe.sections[.text].size > 56000`   |
| pe.sections[].md5   | MD5 hash of the specified section | `pe.sections[.text].md5 = '0464997eb36c70083164c666d53c6af3'`   |
| pe.symbols   | Imported symbols | `pe.symbols in ('GetTextFaceW', 'GetProcessHeap')`   |
| pe.imports   | Imported dynamic linked libraries | `pe.imports in ('msvcrt.dll', 'GDI32.dll')`   |
| pe.resources  | Version and other PE resources | `pe.resources[FileDescription] = 'Notepad'`   |
| pe.company   | Internal company name of the file provided at compile-time | `pe.company = 'Microsoft Corporation'`  |
| pe.copyright | Copyright notice for the file emitted at compile-time | `pe.company = '© Microsoft Corporation'`  |
| pe.description   | Internal description of the file provided at compile-time | `pe.description = 'Notepad'`   |
| pe.file.name   | Original file name supplied at compile-time | `pe.file.name = 'NOTEPAD.EXE'`   |
| pe.file.version   | File version supplied at compile-time | `pe.file.version = '10.0.18362.693 (WinBuild.160101.0800)'`   |
| pe.product   | Internal product name of the file provided at compile-time | `pe.product = 'Microsoft® Windows® Operating System'`   |
| pe.product.name   | Internal product version of the file provided at compile-time | `pe.product.version = '10.0.18362.693'`   |
| pe.is_dll   | Indicates if the loaded image or a created file is a DLL | `pe.is_dll`   |
| pe.is_driver   | Indicates if the loaded image or a created file is a driver | `pe.is_driver`   |
| pe.is_exec   | Indicates if the loaded image or a created file is an executable | `pe.is_exec`   |
| pe.is_dotnet   | Indicates if the PE contains CLR (Common Language Runtime) data | `pe.is_dotnet`   |
| pe.is_signed   | Indicates if the PE has embedded or catalog signature | `pe.is_signed`   |
| pe.is_trusted   | Indicates if the PE certificate chain is trusted | `pe.is_trusted`   |
| pe.imphash   | Import hash | `pe.impash = '5d3861c5c547f8a34e471ba273a732b2'`   |
| pe.anomalies   | Contains PE anomalies detected during parsing | `pe.anomalies in ('number of sections is 0')`   |
| pe.cert.serial  | PE certificate serial number | `pe.cert.serial = '330000023241fb59996dcc4dff000000000232'`   |
| pe.cert.subject  | PE certificate subject | `pe.cert.subject contains 'Washington, Redmond, Microsoft Corporation'`   |
| pe.cert.issuer  | PE certificate CA | `pe.cert.issuer contains 'US, Washington, Redmond, Microsoft Windows Production PCA 2011'`   |
| pe.cert.after  | PE certificate expiration date | `pe.cert.after contains '2024-02-01 00:05:42 +0000 UTC'`   |
| pe.cert.before  | PE certificate enrollment date | `pe.cert.before contains '2024-02-01 00:05:42 +0000 UTC'`   |
| pe.is_modified | Indicates if on-disk and in-memory PE headers differ | `pe.is_modified'`   |
| pe.is_modified | Indicates if on-disk and in-memory PE headers differ | `pe.is_modified'`   |
| pe.ps.child.file.name | Original file name of the child process executable supplied at compile-time | `pe.ps.child.file.name = 'NOTEPAD.EXE'` |
