`Kevent` is the fundamental data structure for transporting kernel events.

Each kernel event structure contains a series of canonical fields that describe the nature of the event such as its name, the process identifier that generated the event and such. The following is the list of all canonical fields.

- **Sequence** is a monotonically increasing integer value that uniquely identifies an event. The sequence value is guaranteed to increment monotonically as long as the machine is not rebooted. After the restart, the sequence is restored to the zero value.
- **PID** represents the process identifier that triggered the kernel event.
- **TID** is the thread identifier connected to the kernel event.
- **CPU** designates the logical CPU core on which the event was originated.
- **Name** is the human-readable event name such as `CreateProcess` or `RegOpenKey`.
- **Timestamp** denotes the timestamp expressed in nanosecond precision as the instant the event occurred.
- **Category** designates the category to which the event pertains, e.g. `file` or `thread`. Each particular category is explained thoroughly in the next
 sections.
- **Description** is a short explanation about the purpose of the event. For example, `CreateFile` kernel event creates or opens a file, directory, I/O device, pipe, console buffer or other block/pseudo device.
- **Host** represents the host name where the event was produced.

### Parameters

Also called as `kparams` in Fibratus parlance, contain each of the event's parameters. Internally, they are modeled as a collection of key/value pairs where the key is mapped to the structure consisting of parameter name, parameter type and the value. An example of the parameter tuple could be the `dip` parameter
that denotes a destination IP address with value `172.17.0.2` and therefore `IPv4` type. Additionally, parameter types can be scalar values, strings, slices, enumerations, and timestamps among others.

### Process state

Each event stores the process state that represents an extended information about the process including its allocated resources such as handles, dynamically-linked libraries, exported environment variables and other attributes. The process state internals are thoroughly explained in the [Process](/kevents/process) events section.

### Metadata

Metadata are an arbitrary sequence of tags in form of key/value pairs that you can squash into the event on behalf of [transformers](/transformers/introduction). A tag can be virtually any string data that you find meaningful to either identify the event or apply filtering/grouping once event is persisted in the data store.
