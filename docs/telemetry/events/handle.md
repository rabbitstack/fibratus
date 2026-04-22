# Handle Events

##### The object manager produces handle events to provision or dispose resources allocated to processes. Resources can be threads, registry keys, files, synchronization primitives and so on. **Fibratus** captures handle creation, destruction, and duplication operations.

?> Handle events are voluminous and they are disabled by default. To enable the collection of handle events either run Fibratus with the `--eventsource.enable-handle=true` flag or activate it permanently by editing the config file.

### `CreateHandle`

`CreateHandle` is captured when the object manager provisions a new handle in the address space of the calling process. The following parameters are associated with the `CreateHandle` event:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `handle_id` | Unique identifier of the handle. |
| `handle_object` | Address of the kernel object to which the handle is associated. |
| `type_id` | Handle type, for example, `File` or `Key` |

### `CloseHandle`

`CloseHandle` event is triggered when the handle is released by the process. It contains the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `handle_id` | Unique identifier of the handle. |
| `handle_name` | Handle name, for example, `\RPC Control\OLEA61B27E13E028C4EA6C286932E80` |
| `handle_object` | Address of the kernel object to which the handle is associated. |
| `type_id` | Handle type, for example, `File` or `Key` |


### `DuplicateHandle`

`DuplicateHandle` event is fired when the process duplicates an object handle. The following parameters are present in this event:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `handle_id` | Duplicated handle identifier. |
| `handle_object` | Address of the duplicated kernel object. |
| `handle_source_id` | Identifier of the handle to be duplicated. |
| `type_id` | Duplicated handle type, for example,  `DxgkCompositionObject` |
| `pid` | Process identifier from which the handle is duplicated. |
| `exe` | Process executable path from which the handle is duplicated. |
| `name` | Process name from which the handle is duplicated. |

### Handle state

During bootstrap, Fibratus builds a snapshot of currently allocated handles. Similarly, when a new process is created Fibratus fetches its handles and attaches them to the process state. However, to optimize memory utilization, the initial handle snapshot and process handle table initialization are disabled by default. You can enable both features by modifying the `--handle.init-snapshot=true` and `--handle.enumerate-handles` config flags respectively or changing the corresponding key in the configuration file.

The handle state contains:

- handle name
- handle type
- the address of the kernel object
- handle identifier
- additional metadata such as `ALPC` port information or mutant count
