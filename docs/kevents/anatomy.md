# Anatomy Of An Event

The **Event** or `kevent` as referred to in Fibratus internal lingo is the fundamental building block that encapsulates the state of the event. The [ETW](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal) **Kernel Logger** provider produces the flow of events in their raw format. This means that the vast majority of the event's parameters lack a meaningful context needed for an intuitive human interpretation. To clarify the previous statement, here are some concrete examples:

- registry keys containing partial paths are typically not very useful. Think of `Settings/Control Panel` key that actually represents the fully qualified `HKEY_CURRENT_USER/Settings/Control Panel` path. Fibratus makes sure to run a hook in the early stage of the kernel event stream to figure out the remaining key name. Aside from this, root keys are represented in the native object manager format, e.g. `REGISTRY\MACHINE` is the key name for the `HKEY_CURRENT_MACHINE` root level key. Fibratus normalizes native root keys to well-known names.
- missing file names in `ReadFile` or `WriteFile` events. These events only contain the address of the file object that obviously doesn't give any hints about the file involved in the I/O operation. Fibratus strives for a best-effort file name resolution. Similarly to native registry key names, the Kernel Logger emits files names in DOS device name format, e.g. `Device\HardDisk4\Windows\System32\kernel32.dll`. Fibratus maps DOS device names to drive letters.
- handle type names are given as integer values. Fibratus takes care of mapping type identifiers to human-readable handle type names such as `File`, `Mutant` or `Key`.

However, this is not the only heavy-lifting task Fibratus does to produce high-quality events. Additionally, events are enriched with various parameters that are not originally present in the ETW payloads.

### Canonical fields

Each event contains a series of canonical fields that describe the nature of the event such as its name, the process identifier that generated the event and such. The following is the list of all canonical fields.

- **Sequence** is a monotonically increasing integer value that uniquely identifies an event. The sequence value is guaranteed to increment monotonically as long as the machine is not rebooted. After the restart, the sequence is restored to the zero value.
- **PID** represents the process identifier that triggered the event.
- **TID** is the thread identifier connected to the event.
- **CPU** designates the logical CPU core on which the event was originated.
- **Name** is the human-readable event name such as `CreateProcess` or `RegOpenKey`.
- **Timestamp** denotes the timestamp expressed in nanosecond precision as the instant the event occurred.
- **Category** designates the category to which the event pertains, e.g. `file` or `thread`. Each particular category is explained thoroughly in the next
 sections. Possible category types are: `registry`, `file`, `net`, `process`, `thread`, `image` and `handle`.
- **Description** is a short explanation about the purpose of the event. For example, `CreateFile` event creates or opens a file, directory, I/O device, pipe, console buffer or other block/pseudo device.
- **Host** represents the host name where the event was produced.

### Parameters

Also called as `kparams` in Fibratus parlance, contain each of the event's parameters. Internally, they are modeled as a collection of key/value pairs where the key is mapped to the structure consisting of parameter name, parameter type and the value. An example of the parameter tuple could be the `dip` parameter
that denotes a destination IP address with value `172.17.0.2` and therefore `IPv4` type. Additionally, parameter types can be scalar values, strings, slices, enumerations, and timestamps among others.

### Process state

Each event stores the process state that represents an extended information about the process including its allocated resources such as handles, dynamically-linked libraries, exported environment variables and other attributes. The process state internals are thoroughly explained in the [Process](/kevents/process) events section.

### Callstack

Callstack reconstructs the sequence of function calls that led to the current thread state. When stack enrichment is enabled (controlled by the `--kstream.stack-enrichment` configuration flag), return addresses obtained directly from kernel space, are symbolized and enriched with a vital context that can be leveraged to boost behavioral detections and reduce false positive alerts. A typical callstack summary is depicted in the snippet above:

```
0x7ffb5c1d0396 C:\WINDOWS\System32\KERNELBASE.dll!CreateProcessW+0x66
0x7ffb5d8e61f4 C:\WINDOWS\System32\KERNEL32.DLL!CreateProcessW+0x54
0x7ffb5c1d0396 C:\WINDOWS\System32\KERNELBASE.dll!CreateProcessW+0x61
0x7ffb3138592e C:\Program Files\JetBrains\GoLand 2021.2.3\jbr\bin\java.dll!Java_java_lang_ProcessImpl_waitForTimeoutInterruptibly+0x3a2
0x7ffb313853b2 C:\Program Files\JetBrains\GoLand 2021.2.3\jbr\bin\java.dll!Java_java_lang_ProcessImpl_create+0x10a
0x2638e59e0a5 unbacked!?
```

Each line is comprised of:

- function call return address (e.g. `0x7ffb5c1d0396`)
- full path of the image/module containing the executed function. If the call is invoked from a floating memory region, then the module name is marked as `unbacked`
- name of the symbol mapping to the return address (e.g. `CreateProcessW`)
- offset within the function body

Stack enrichment is performed for the following event set:

- `CreateProcess`
- `CreateThread`
- `TerminateThread`
- `SetThreadContext`
- `LoadImage`
- `RegCreateKey`
- `RegDeleteKey`
- `RegSetValue`
- `RegDeleteValue`
- `CreateFile` (full symbolization is performed on events where create disposition is different than `OPEN`)
- `DeleteFile`
- `RenameFile`

To enable stack enrichment for kernel space return addresses, the `symbolize-kernel-addresses` config option needs to be set to `true`. Callstack data is used by [filter fields](/filters/fields?id=callstack) to permit crafting advanced detection rules.

### Metadata

Metadata are an arbitrary sequence of tags in form of key/value pairs that you can squash into the event on behalf of [transformers](/transformers/introduction). A tag can be virtually any string data that you find meaningful to either identify the event or apply filtering/grouping once event is persisted in the data store.
