# Registry events

Registry events are triggered when processes access or modify the registry structure.

#### RegCreateKey

Creates a new registry key or opens the key if it already exists. This event has the following parameters:

- `key_handle` represents the handle to the registry key. In reality, this value represents the address of the KCB (Key Control Block) structure in kernel space.
- `key_name` is the name of the registry key including the root key. (e.g. `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control`)
- `status` contains the result of the registry operation (e.g. `key not found`)

#### RegDeleteKey

Deletes a subkey and all its values. This event has the same group of parameters as the `RegCreateKey` event.

#### RegOpenKey

Opens a registry key. This event has the same group of parameters as the `RegCreateKey` event.

#### RegQueryKey

Enumerates the subkeys of the specified key. The first subkey is referenced by index number 0, the second key by 1, and so on.

- `key_handle` represents the handle to the registry key.
- `key_name` is the name of the registry key whose subkeys are enumerated.
- `status` contains the result of the registry operation (e.g. `key not found`)

#### RegQueryValue

Fetches the data associated with the value of a registry key. This event has the same group of parameters as the `RegCreateKey` event, except that the base name of the registry key path is the value name.

#### RegSetValue

Sets the data associated with the value of a registry key. This event contains the following parameters:

- `key_handle` represents the handle to the registry key.
- `key_name` represents the fully qualified name of the registry value whose data is modified
- `status` contains the result of the registry operation (e.g. `success`)
- `value` contains the payload of the value being set
- `type` represents the registry value type. Possible value are: `REG_DWORD`, `REG_QWORD`, `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_BINARY`, `UNKNOWN`.

#### RegDeleteValue

Deletes the registry value. This event has the same parameters as the `RegCreateKey` event.
