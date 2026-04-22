# Registry Events

##### Registry events are triggered when processes access or modify the registry structure, such as creating new keys, altering registry key values or opening a handle to the registry key.

### `RegCreateKey` `RegDeleteKey` `RegOpenKey` `RegCloseKey` `RegQueryKey`

Creates a new registry key or opens the key if it already exists. Deletes a subkey and all its values. Opens a registry key. Closes the registry key. Enumerates the subkeys of the specified key. All of these events share a common parameter schema:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `key_handle` | Represents the address of the [KCB](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-regkcb) (Key Control Block) structure in kernel space. |
| `key_path` | Full registry path involved in the operation, for example, `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control` |
| `status` | System status code of the registry operation, for example, `More data is available` |

### `RegQueryValue`

`RegQueryValue` is captured when the process retrieves the data from registry value. This event contains the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `key_handle` | Represents the address of the [KCB](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-regkcb) (Key Control Block) structure in kernel space. |
| `key_path` | Full path of the registry value, for example, `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\GpSvcDebugLevel` |
| `status` | System status code of the registry operation, for example, `The system cannot find the file specified` |


### `RegSetValue`

`RegSetValue` event is triggered when registry data is set in the value. This event contains the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `key_handle` | Represents the address of the [KCB](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-regkcb) (Key Control Block) structure in kernel space. |
| `key_path` | Full path of the registry value, for example, `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\GpSvcDebugLevel` |
| `status` | System status code of the registry operation, for example, `Success` |
| `data` | Value data being stored. |
| `value_type` | Registry value type. Possible values include `REG_DWORD`, `REG_QWORD`, `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_BINARY`, `UNKNOWN` |

### `RegDeleteValue`

`RegDeleteValue` is captured when the registry values is deleted. This event contains the following parameters:

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `key_handle` | Represents the address of the [KCB](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-regkcb) (Key Control Block) structure in kernel space. |
| `key_path` | Full path of the registry value, for example, `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System\GpSvcDebugLevel` |
| `status` | System status code of the registry operation, for example, `Success` |
| `value_type` | Registry value type. Possible values include `REG_DWORD`, `REG_QWORD`, `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_BINARY`, `UNKNOWN` |