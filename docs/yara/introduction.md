# Pattern Matching Swiss Knife

[YARA](https://virustotal.github.io/yara/) is a prominent tool for binary pattern matching that aims to streamline and accelerate the classification of malware specimens. Fibratus interacts with the `libyara` through C bindings. The `libyara` dependency is statically linked, so no further software needs to be installed.

**Fibratus/YARA** tandem aims to detect in-memory threats and malicious **PE** files by reacting on various signals including:

- new process creation
- loading of an unsigned/untrusted executable/DLL or when the executable/DLL is loaded from the unbacked memory region
- creation of executable, DLL, or driver PE files
- creation of [ADS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e2b19412-a925-4360-b009-86e3b8a020c8) (Alternate Data Streams)
- RWX memory allocations
- mapping of a suspicious view of section
- writing a binary registry value

The YARA scanner is not enabled by default, but you can do that by modifying the `yara.enabled` key in the configuration file.
