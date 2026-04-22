# Module Events

##### Module events occur when a process loads/unloads a dynamic linked library, executable or a kernel driver. The loading can happen in the local or remote process. These events are represented by `LoadModule` and `UnloadModule` types respectively. The following list describes all available parameters present in module events captured by **Fibratus**

### `LoadModule` `UnloadModule`

| PARAMETER  | DESCRIPTION |
| :---        |    :----   |
| `file_path` | Full path name of the module file, for example, `C:\Windows\system32\kernel32.dll` |
| `module_size` | Represents the size of the mapped module region. |
| `checksum` | Represents the module checksum digest. |
| `base_address` | Base address of the process in which the image is loaded/unloaded. |
| `default_address` | Represents the module base address. |
| `pid` | Specifies the process identifier where the module is loaded/unloaded. |
| `signature_type` | Describes the type of the digital signature. Can be `NONE`, `EMBEDDED`, `CACHED`, `CATALOG_CACHED`, `CATALOG_UNCACHED`, `CATALOG_HINT`, `PACKAGE_CATALOG` and `FILE_VERIFIED`. This parameter is a best-effort hint. The kernel doesn't always verify signatures on module load and can report false positives for the signature type.  |
| `signature_level` | Describes the signature level. This parameter is a best-effort hint. The kernel doesn't always verify signatures on module load and can report false positives for the signature level. |
