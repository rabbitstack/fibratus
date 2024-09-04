# Paths

As you may have already noticed, different entities can appear in filter fields. For example, `ps` is the root entity that designates the source of process-related values. To access the value from the entity, the __path__ expression is used as a sequence of period-delimited segments that yield the final value. Thus, the `ps.name` field path gives the process name. Paths can be nested, like `ps.parent.handles`, to collect all handle names of the parent process.

Paths can also be constructed in combination with array or map indexing.

### Process ancestry {docsify-ignore}

Walking the process tree is a useful feature when you want to capture events produced by the process that is a descendant of particular processes. For this purpose, various path segments with map indexing are available.

#### Depth indexing

Fetches the ancestor that is located at a specified depth starting from the current process. `ps.ancestor[1]` yields the immediate parent process and it is equivalent to using the `ps.parent` field. Imagine the following process tree:

```
├───wininit.exe
│   └───services.exe
│       └───svchost.exe
│           └───dllhost.exe
│               ├───cmd.exe
│               └───winword.exe
```

Assuming the `winword.exe` is the current process generating the event, we could write the following filter expression to check its ancestors:

```
$ fibratus run --forward ps.ancestor[1].name = 'dllhost.exe' or ps.ancestor[3].name = 'services.exe'
```

#### Root indexing

To filter events where their ancestor process is the root of the process tree, you can employ the `root` key. Considering the same process tree as above, we can construct the following filter:

```
$ fibratus run --forward ps.ancestor[root].name = 'wininit.exe'
```

#### Any indexing

If you want to match on multiple ancestors, use the `any` key. The following expression would filter all events where the process generating them has `svchost.exe` or `dllhost.exe` ancestors:

```
$ fibratus run --forward ps.ancestor[any].name in ('svchost.exe', 'dllhost.exe')
```

Besides the process name, several other path segments are available for returning the ancestor data:

- `.pid` returns the process identifier
- `.args` gives process command line arguments as a list of strings
- `.comm` returns the process command line argument as a raw string
- `.cwd` fetches the process current working directory
- `.exe` returns the process image path
- `.sid` returns the process user/domain name
- `.sessionid` returns the process session identifier

!> `any` returns a list of values specified by the path segment, and thus requires operators that evaluate on lists instead of simple primitive values.

### Portable Executable {docsify-ignore}

[Portable Executable](/pe/introduction) introspection allows for utilizing the PE metadata in filters. See other [fields](filters/fields?id=pe) that can be used to narrow down events by PE data.

#### Section indexing

You can use the section name as an index to retrieve the data used for filter matching. For example, `ps.pe.sections[.debug$].size` would fetch the size of the `.debug$` section.

Available path segments:

- `.entropy` returns the section entropy
- `.md5` returns the section MD5 hash value

#### Resource indexing

PE [resources](/pe/resources) are accessed by the resource name. For example, the following filter would match all events where process PE resources contain the `github` company.

```
$ fibratus run --forward pe.resources[CompanyName] contains 'github'
```

### Modules {docsify-ignore}

Process modules can be accessed by the module name. The file extension is omitted from the module name. For example:

```
$ fibratus run --forward ps.modules['crypt'].size > 1024
```

Other paths segments you can use in modules indexing:

- `.base.address` returns the	base address of the process in which the module is loaded
- `.checksum`	returns the checksum of the module file
- `.size` gives the module size
- `.default.address` returns the default image address

### Callstack {docsify-ignore}

[Stack enrichment](/kevents/anatomy?id=callstack) attaches call frames that can be accessed by various kinds of indices:

- `ustart` accesses the first userspace callstack frame. (e.g. `thread.callstack[ustart].address = '2638e59e0a5'`)
- `uend` accesses the last (top-most) userspace callstack frame (e.g. `thread.callstack[uend].address = '7ffb5c1d0396'`)
- `kstart` accesses the first kernel space callstack frame (e.g. `thread.callstack[kstart].address = 'fffff8072ebc1f6f'`)
- `kend` accesses the last (top-most) kernel space callstack frame (e.g. `thread.callstack[kend].address = 'fffff8072eb8961b'`)
- frame index. The index `0` represents the least-recent frame, usually the base thread initialization frame. (e.g. `thread.callstack[2].symbol = 'Java_java_lang_ProcessImpl_create'`)
- module name. Returns the first frame that maps to the given module name. (e.g. `thread.callstack[kernelbase.dll].symbol = 'CreateProcessW'`)

### Environment variables {docsify-ignore}

You can access process environment variables by providing the name of the environment variable. Alternatively, you can provide the prefix.

```
$ fibratus run --forward ps.envs['MOZ_CRASHREPORTER'] = 'C:\\Program Files\\Firefox'
```

Or, supplying the prefix

```
$ fibratus run --forward ps.envs['MOZ_CRASH'] = 'C:\\Program Files\\Firefox'
```