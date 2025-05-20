# Iterators

`foreach` idiom adds iteration capabilities to the rule language. Under the hood, `foreach` is implemented as a function that accepts three required and multiple optional arguments. The first argument is the `iterable` value typically yielded by the pseudo field. 

The function recognizes process internal state collections such as modules, threads, memory mappings, or thread stack frames. Obviously, it is also possible to iterate over simple string slices. The second argument represents the `bound variable` which is an item associated with every element in the slice. The bound variable is accessed in the third argument, the `predicate`. It is usually followed by the `segment` that denotes the accessed value. Unsurprisingly, the predicate is commonly a binary expression that can be formed of `not/paren` expressions, other functions, and so on. The predicate is executed on every item in the slice. If the predicate evaluates to true, the function also returns the true value.

Lastly, foreach function can receive an optional `list of fields` from the outer context, i.e. outside predicate loop. Therefore, for the predicate to access the field not defined within the scope of the iterable, it must capture the field first.

Some examples of the `foreach` usage:

- Traverses process modules and return true if the module path matches the pattern

```
foreach(ps._modules, $mod, $mod.path imatches '?:\\Windows\\System32\\us?r32.dll')
```

- For each process ancestor, check if the ancestor is `services.exe` and the current process is protected. In this example, the `ps.is_protected` field is captured before its usage in the predicate

```
foreach(ps._ancestors, $proc, $proc.name = 'services.exe' and ps.is_protected, ps.is_protected)
```

## Process iterators {docsify-ignore}

The `ps.ancestor` returns all ancestor names of the process generating the event. Alternatively, the filter field can accept an argument. In case of the `ps.ancestor` field, the argument indicates the ancestor level. Given the process tree below and assuming the current process generating the event is `cmd.exe`, the field with an optional level argument yields the values as follows:

```
├───wininit.exe
│   └───services.exe
│       └───svchost.exe
│           └───dllhost.exe
│               ├───cmd.exe
│               └───winword.exe
```

- `ps.ancestor[1]` returns `dllhost.exe`
- `ps.ancestor[3]` returns `services.exe`
- `ps.ancestor[4]` returns `wininit.exe`

If the argument is omitted, the slice with all ancestor names is returned. The `ps.ancestor` field can only yield a single process attribute - process name. To build complex conditions involving different process attribute, we can use the `foreach` construct. The bound variable associated with the `ps._ancestors` pseudo field can have the any of the segments:

| Segment Name  | Description |
| :---        |    :----    |
|`pid` | Process identifier |
|`name` | Process name |
|`args` | Process command line arguments as a list of strings |
|`cmdline` | Process command line argument as a raw string |
|`cwd`  | Process current working directory |
|`exe` | Process image path |
|`sid` | Process SID (security identifier) |
|`sessionid` | Process session identifier |
|`username` | User name associated with the process security context |
|`domain`  | Domain associated with the process security context |

Examples

- Check if the ancestor has one of the particular process identifiers and the pid belongs to the `services.exe` process

```
foreach(ps._ancestors, $proc, $proc.pid in (2034, 343) and $proc.name = 'services.exe')
```

- Check if the ancestor starts with the specific security identifier and the pid belongs to the `svchost.exe` process

```
foreach(ps._ancestors, $proc, $proc.sid imatches `S-1-5*` and $proc.name = 'svchost.exe')
```


### Modules {docsify-ignore}

The `ps._modules` pseudo field returns the process modules iterable. Available module segments are:


| Segment Name  | Description |
| :---        |    :----    |
|`address` | Base address of the process in which the module is loaded|
|`checksum` | Module checksum |
|`size` | Module size in terms of allocated virtual address space |
|`name` | Module name |
|`path`  | Full module path |

Examples

- Check the virtual memory space size of the specific module

```
foreach(ps._modules, $mod, $mod.size >= 212354 and $mod.name imatches '*winhttp.dll')
```

### Threads {docsify-ignore}

The `ps._threads` pseudo field yields all of the process running threads. Available thread segments are:


| Segment Name  | Description |
| :---        |    :----    |
|`tid` | Thread identifier |
|`start_address` | The address of the function executed by the thread |
|`user_stack_base` | The base address of the thread userspace stack |
|`user_stack_limit` | The address denoting the thread userspace stack limit  |
|`kernel_stack_base`  | The base address of the thread kernel stack |
|`kernel_stack_limit`  | he address denoting the thread kernel stack limit |

### Memory mappings {docsify-ignore}

Process memory mappings (also known as sections) can be accessed via the `ps._mmaps` pseudo field. Available memory mappings segments are:

| Segment Name  | Description |
| :---        |    :----    |
|`address` | Address where the section is mapped within the process address space |
|`type` | The type of the memory mapping. For example, `DATA`. |
|`size` | Size in bytes of the memory mapping |
|`protection` | Protection attributes of the mapped memory section |
|`path`  | If the memory mapping is backed by a physical file, indicates the path of the file |

### Environment variables {docsify-ignore}

You can access process environment variables by providing the name of the environment variable. Alternatively, you can provide the prefix.

```
ps.envs['MOZ_CRASHREPORTER'] = 'C:\\Program Files\\Firefox'
```

Or, supplying the prefix

```
ps.envs['MOZ_CRASH'] = 'C:\\Program Files\\Firefox'
```

It is also possible to retrieve all environment variables as a list of colon separated key/value pairs. Example using the `foreach` idiom:

```
foreach(ps.envs, $env, substr($env, 0, indexof($env, ':')) = 'OS')
```

## Portable Executable iterators {docsify-ignore}

[Portable Executable](/pe/introduction) introspection allows for utilizing the PE metadata in filters. See other [fields](filters/fields?id=pe) that can be used to narrow down events by PE data.

### Sections {docsify-ignore}

The `pe._sections` pseudo field yields all of the executable image PE sections. Available section segments are:

| Segment Name  | Description |
| :---        |    :----    |
|`name` | Section name. For example, `.debug$` |
|`size` | Section size in bytes |
|`entropy` | Section entropy |
|`md5` | Section MD5 hash |

### Resources {docsify-ignore}

PE [resources](/pe/resources) can be accessed by the resource name. Alternatively, it is possible to obtain all the resources as a list separated by the colon delimiter:

```
pe.resources iin ('FileDescription:Notepad')
```


## Callstack {docsify-ignore}

[Stack enrichment](/kevents/anatomy?id=callstack) attaches call frames that can be accessed by the `thread._callstack` pseudo field. Available callstsack segments are:

| Segment Name  | Description |
| :---        |    :----    |
|`address` | Symbol address |
|`offset` | Symbol offset |
|`symbol` | Symbol name |
|`module` | Module name containing the frame |
|`allocation_size` | Private allocation size |
|`protection` | Frame protection mask |
|`is_unbacked` | Indicates if the frame is unbacked |
|`callsite_leading_assembly` | Callsite leading assembly instructions |
|`callsite_trailing_assembly` | Callsite trailing assembly instructions|
|`module.signature.is_signed` | Indicates if the frame module is signed |
|`module.signature.is_trusted` | Indicates if the frame module signature is trusted |
|`module.signature.cert.subject` | Frame module signature certificate subject |
|`module.signature.cert.issuer` | Frame module signature certificate issuer |

Examples:

- Determine if the frame protection is RWX (Read-Write-Execute)

```
foreach(thread._callstack, $frame, $frame.protection = 'RWX')
```

- Determine if the frame trailing assembly contain the `syscall` instruction and the frame resides in the floating memory region

```
foreach(thread._callstack, $frame, $frame.callsite_trailing_assembly matches '*mov r10, rcx|mov eax, 0x*|syscall*' and $frame.module = 'unbacked')
```