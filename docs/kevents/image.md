# Image events

Image events occur when a process loads/unloads a dynamic linked library, executable or the kernel driver. The loading can happen in the local or remote process. These events are represented by `LoadImage` and `UnloadImage` types respectively. The following list describes all available parameters present in DLL events.

- `file_name` denotes the full path name of the image file. (e.g. `C:\Windows\system32\kernel32.dll`)
- `image_size` represents the image size in bytes.
- `checksum` represents the image checksum digest.
- `base_address` is the base address of the process in which the image is loaded/unloaded.
- `default_address` represents the image's base address.
- `pid` that specifies the process identifier where the image was loaded/unloaded.


Additionally, `LoadImage` events contain the following parameters.

- `is_dll` determines if the image is a DLL object. 
- `is_driver` determines if the image is a kernel driver. 
- `is_exec` determines if the image being loaded is an executable.
