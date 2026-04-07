# Module events

##### Module events occur when a process loads/unloads a dynamic linked library, executable or a kernel driver. The loading can happen in the local or remote process. These events are represented by `LoadImage` and `UnloadImage` types respectively. The following list describes all available parameters present in module events captured by **Fibratus**

### `LoadImage` `UnloadImage`

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `file_path` | Full path name of the module file, for example, `C:\Windows\system32\kernel32.dll` |
| `image_size` | Represents the size of the mapped module region. |
| `checksum` | Represents the module checksum digest. |
| `base_address` | Base address of the process in which the image is loaded/unloaded. |
| `default_address` | Represents the module base address. |
| `pid` | Specifies the process identifier where the module is loaded/unloaded. |
