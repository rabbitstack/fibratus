# Resources

Fibratus reads version resources from the PE resource directory. The resource contains information about the exeucutable as its version number, its intended operating system, and its original filename. An example of version resources read by Fibratus:

```
CompanyName: Microsoft Corporation
FileDescription: Notepad
FileVersion: 10.0.18362.693 (WinBuild.160101.0800)
InternalName: Notepad
LegalCopyright: © Microsoft Corporation. All rights reserved.
OriginalFilename: NOTEPAD.EXE
ProductName: Microsoft® Windows® Operating System
ProductVersion: 10.0.18362.693
```

You can use any of these resource entries in filter expressions. For example, the `pe.resources[FileDescription] = 'Notepad'` filter matches any event where the `FileDescription` resource is equal to `Notepad`.

To enable resource parsing, it is necessary to set the `read-resources` option to `true`.
