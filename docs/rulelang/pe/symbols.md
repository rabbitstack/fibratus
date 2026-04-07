# Symbols

 Symbols or functions referred to by the binary that are expected to be satisfied by other libraries at dynamic load time are located in the Import Address Table (IAT). Fibratus parses this table and extracts all symbols names as well as the dynamic libraries referenced by the binary. Symbol names can be `URLDownloadToFileA` or `WriteFile`.

 To activate symbol parsing it is necessary to enable the `read-symbols` option.

 From the filtering perspective,  you can write `pe.symbols in ('GetTextFaceW', 'GetProcessHeap')` or `pe.imports in ('msvcrt.dll', 'GDI32.dll')` to filter events where the originating process contains the provided symbols or imports in its binary PE data.
