# Pattern Matching Swiss Knife

[YARA](https://virustotal.github.io/yara/) is a prominent tool for binary pattern matching that aims to streamline and accelerate the classification of malware specimens. Fibratus interacts with the `libyara` through C bindings. The `libyara` dependency is statically linked, so no further software needs to be installed.

**Fibratus/YARA** tandem seeks to automate the classification of malicious processes and loadable modules by proactively scanning and alerting whenever a process is started.

The YARA scanner is not enabled by default, but you can do that by modifying the `yara.enabled` key in the configuration file.
