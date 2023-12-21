# Image events

Image events occur when a process loads/unloads a dynamic linked library, executable or the kernel driver. The loading can happen in the local or remote process. These events are represented by `LoadImage` and `UnloadImage` types respectively. The following list describes all available parameters present in DLL events.

- `file_name` denotes the full path name of the image file. (e.g. `C:\Windows\system32\kernel32.dll`)
- `image_size` represents the image size in bytes.
- `checksum` represents the image checksum digest.
- `base_address` is the base address of the process in which the image is loaded/unloaded.
- `default_address` represents the image's base address.
- `pid` that specifies the process identifier where the image was loaded/unloaded.
- `cert_issuer` represents the image certificate issuer. (e.g. `US, Washington, Redmond, Microsoft Windows Production PCA 2011`)
- `cert_not_after` indicates the timestamp after the certificate is no longer valid
- `cert_not_before` indicates the timestamp of the certificate enrollment date
- `cert_serial` represents the certificate serial number (e.g. `330000041331bc198807a90774000000000413`)
- `cert_subject` denotes the certificate subject (e.g. `US, Washington, Redmond, Microsoft Corporation, Microsoft Windows`)
- `signature_level` specifies the image signature level at which the code was verified. It can be one of the following values: 
`UNCHECKED`, `UNSIGNED`, `ENTERPRISE`, `DEVELOPER`, `AUTHENTICODE`, `STORE_PPL`, `STORE`, `ANTIMALWARE`, `MICROSOFT`,   `CUSTOM_4`, `CUSTOM_5`, `DYNAMIC_CODEGEN`, `WINDOWS`, `CUSTOM_7`, `WINDOWS_TCB`, `CUSTOM_6`.    
- `signature_type` designates the signature type. It is represented by one of the following types: `NONE`, `EMBEDDED`, `CACHED`, `CATALOG_CACHED`, `CATALOG_UNCACHED`, `CATALOG_HINT`, `PACKAGE_CATALOG`, `FILE_VERIFIED`. 

Additionally, `LoadImage` events contain the following parameters.

- `is_dll` determines if the image is a DLL object. 
- `is_driver` determines if the image is a kernel driver. 
- `is_exec` determines if the image being loaded is an executable.
