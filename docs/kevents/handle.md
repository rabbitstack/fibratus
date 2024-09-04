# Handle events

The object manager produces handle events to provision or dispose Windows resources allocated to processes. Resources can be threads, registry keys, files, synchronization primitives and so on.

!> Handle events can be quite voluminous and they are disabled by default. To enable the collection of handle events either run Fibratus with the `--kstream.enable-handle=true` flag or activate them permanently by editing the config file.

#### CreateHandle

Provisions a new handle in the address space of the calling process. The following parameters are associated with the `CreateHandle` event:

- `handle_id` represents the unique identifier of the handle.
- `handle_object` represents the address of the kernel object to which the handle is associated
- `handle_name` denotes the handle name. (e.g. `\RPC Control\OLEA61B27E13E028C4EA6C286932E80`)
- `type_id` designates the handle type. (e.g. `ALPC Port`, `File`, `Key`)

#### CloseHandle

The `CloseHandle` event is triggered when the handle is released by the process. It contains the same set of parameters found in the `CreateHandle` event.

#### DuplicateHandle

This event is fired when the process duplicates an object handle. The following parameters are present in `DuplicateHandle` events:

- `handle_id` represents the duplicated handle identifier.
- `handle_object` represents the address of the duplicated kernel object
- `handle_source_id` represents the identifier of the handle to be duplicated.
- `type_id` designates the duplicated handle type. (e.g. `DxgkCompositionObject`)
- `pid`, `exe`, `name` represent the source process identifier, process executable path, and the process image name respectively.

### Handle state {docsify-ignore}

During bootstrap, Fibratus builds a snapshot of currently allocated handles. Similarly, when a new process is created Fibratus fetches its handles and attaches them to the process state. However, to optimize memory utilization, the initial handle snapshot and process handle table initialization are disabled by default. You can enable both features by modifying the `--handle.init-snapshot=true` and `--handle.enumerate-handles` config flags respectively or changing the corresponding key in the configuration file.

The handle state contains:

- handle name
- handle type
- the address of the kernel object
- handle identifier
- additional metadata such as `ALPC` port information or mutant count
