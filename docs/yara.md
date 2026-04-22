# Memory scanning

##### [YARA](https://virustotal.github.io/yara/) is a widely adopted framework for binary pattern matching and malware classification. It allows to define rules that describe suspicious or malicious artifacts based on strings, byte patterns, and binary format properties.

Fibratus integrates YARA directly into its event processing pipeline to enable real-time scanning of memory and binaries, focusing on in-memory threats such as fileless malware, suspicious [PE](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) artifacts, and abnormal memory behavior.

Memory or binary scanning is triggered in response to various behavioral signals:

- new process creation
- loading of an unsigned/untrusted executable/DLL or when the executable/DLL is loaded from the unbacked memory region
- creation of executable, DLL, or driver PE files
- creation of [ADS](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e2b19412-a925-4360-b009-86e3b8a020c8) (Alternate Data Streams)
- RWX memory allocations
- mapping of a suspicious view of section
- writing a binary registry value

Fibratus embeds [`libyara`](https://yara.readthedocs.io/en/stable/capi.html) via native bindings. The YARA engine is statically linked so no additional installation is required. Rules are compiled and executed inside the Fibratus runtime.

!> Fibratus detection rules use a custom, purpose-built format tailored to its event processing and detection  model. In contrast, YARA rules follow a widely adopted industry standard for pattern matching and malware classification. Because they serve different purposes and operate independently, Fibratus does not include built-in YARA rules. However, you can integrate and run community-maintained [YARA rules](https://github.com/yara-rules/rules) alongside Fibratus.


## Scanning

The YARA scanner is disabled by default. To enable it, set the `yara.enabled` option in the configuration file.

For the scanner to function, YARA rules must be compiled and loaded into the engine. You can do this by specifying file system paths in the `yara.rule.paths` configuration option. These directories are scanned recursively for `.yar` files. Alternatively, rules can be defined inline as strings directly within the configuration file.

Alerts generated from rule matches are automatically dispatched through all configured alert senders.
When an event matches a YARA rule, its metadata is enriched with the corresponding match details. The `yara.matches` field contains a JSON array where each object represents a YARA rule match.

## Configuration

YARA scanner related options are located in the `yara` section of the configuration file.

### `enabled`

Indicates if the YARA scanner is enabled.

### `rule`

The `rule` key contains various nested keys. The `paths` key identifies directories that contain YARA rule definitions. It is also possible to link each directory to YARA namespace. The `strings` key allows defining inline YARA rules. Example:

```python
rule:
  paths:
    - path: C:\\yara-rules
      namespace: default
    - path: C:\\pdf-rules
      namespace: pdf

  strings:
    - string: rule test : tag1 { meta: author = \"Hilko Bengen\" strings: $a = \"abc\" fullword condition: $a }
      namespace: notepad
```

### `alert-template`

Specifies templates for the alert text in Go [templating](https://golang.org/pkg/text/template) language.

### `fastscan`

Determines when multiple matches of the same string can be avoided when not necessary.

### `scan-timeout`

Specifies the timeout for the scanner. If the timeout is reached, the scan operation is cancelled.

### `skip-files`

Indicates whether file scanning is disabled. This affects the scan triggered by image loading, create file, and file mapping operations.

### `skip-allocs`

Indicates whether scanning on suspicious memory allocations is disabled.


### `skip-mmaps`

Indicates whether scanning on suspicious mappings of sections is disabled.

### `skip-registry`

Indicates whether registry value scanning is disabled.


### `excluded-files`

Contains the list of the comma-separated file paths that shouldn't be scanned. Wildcard matching is supported. For example:

```python
excluded-files:
	- ?:\\Windows\\System32\\kernel32.dll
```

### `excluded-procs`

Contains the list of the comma-separated process executable paths that shouldn't be scanned. Wildcard matching is supported.
