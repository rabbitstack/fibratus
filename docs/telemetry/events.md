# Anatomy Of An Event

**Event** encapsulates the state that is fundamental for assertion against the rule engine. Most [ETW](https://docs.microsoft.com/en-us/windows/win32/etw/event-tracing-portal) providers such as **Kernel Logger** produce the flow of events in raw format. This means that the vast majority of the event's parameters lack a meaningful context needed for an intuitive human interpretation. To clarify the previous statement, here are some concrete examples:

- Registry keys containing partial paths are typically not very useful. Think of `Settings/Control Panel` key that actually represents the fully qualified `HKEY_CURRENT_USER/Settings/Control Panel` path. Fibratus makes sure to run a hook in the early stage of the event stream to reconstruct the full registry path. Aside from this, root keys are represented in the native object manager format, for example, `REGISTRY\MACHINE` is the key name for the `HKEY_CURRENT_MACHINE` root level key. Fibratus normalizes native root keys to well-known names.
- Missing file paths in `ReadFile` or `WriteFile` events. These events contain only the address of the file object that obviously doesn't give any hints about the file path involved in the I/O operation. Fibratus strives for a best-effort file name resolution. Similarly to native registry key names, the Kernel Logger emits files names in DOS device name format, for example, `Device\HardDisk4\Windows\System32\kernel32.dll`. Fibratus maps DOS device names to drive letters.
- Handle type names are given as integer values. Fibratus takes care of mapping type identifiers to human-readable handle type names such as `File`, `Mutant` or `Key`.

This is not the only heavy-lifting tasks Fibratus performs to produce high-quality events. Additionally, events are enriched with various parameters that are not originally present in ETW payloads.

### Canonical fields

Each event contains a series of canonical fields that describe the nature of the event such as its name, the process identifier that generated the event and such. Canonical fields include:

- `Sequence` is a monotonically increasing integer value that uniquely identifies an event. The sequence value is guaranteed to increment monotonically as long as the machine is not rebooted. On machine reboot, the sequence value is reset.
- `PID` represents the process identifier that triggered the event
- `TID` is the thread identifier connected to the event
- `CPU` designates the logical CPU core on which the event was originated
- `Name` is the human-readable event name such as `CreateProcess` or `VirtualAlloc`
- `Timestamp` denotes the timestamp expressed in nanosecond precision as the instant the event occurred
- `Category` designates the category to which the event pertains, for example, `file` or `thread`
- `Host` represents the host name where the event was produced

### Parameters

Internally, event parameters are modeled as a collection of key/value pairs. The key is mapped to the structure consisting of parameter name, parameter type and the value. An example of the parameter tuple could be the `dip` parameter that denotes a destination IP address with value `172.17.0.2` and therefore `IPv4` type. Parameter types can be scalar values, strings, slices, enumerations, and timestamps among others.

### Process state

Each event has attached process state that represents the contextual information about the process including its name, command line, user, token integrity level, allocated resources such as handles, dynamically-linked libraries, environment variables and other attributes. The process state internals are thoroughly explained in the [Process](process.md) events section.

### Callstacks

[Callstacks](../../callstacks.md) provide detailed insight into the execution context of system events by capturing the sequence of function calls (stack frames) that led to a particular action, such as a file write, process creation, or registry state manipulation.

### Metadata

Metadata are arbitrary tags composed of key/value pairs. Event metadata are decorated via [transformers](../transformers/transformers.md). Tags can hold any string values employed for filtering, grouping or other purposes.
