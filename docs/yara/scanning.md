# Scanning Processes

For the YARA scanner to operate correctly, the rules have to be compiled and loaded into the engine. This is accomplished by providing file system paths with YARA rule definitions in the `rule.paths` configuration keys. The directories are scanned recursively for any `.yar` file. Alternatively, it is possible to provide the rules as inline strings directly in the Fibratus configuration file.

### Configuration {docsify-ignore}

YARA scanner related options are located in the `yara` section of the configuration file.

#### enabled

Indicates if the YARA scanner is enabled. When enabled, each newly created process is scanned for pattern matches.

**default**: `false`

#### rule

The `rule` key contains various nested keys. The `paths` key identifies directories that hold the YARA rule definitions. It is also possible to link each directory to YARA namespace. The `strings` key allows for defining inline YARA rules. Example:

```
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

#### alert-template:

Specifies templates for the alert text in Go [templating](https://golang.org/pkg/text/template) language. 


#### fastscan

Determines when multiple matches of the same string can be avoided when not necessary.

**default**: `true`

#### scan-timeout

Specifies the timeout for the scanner. If the timeout is reached, the scan operation is cancelled.

**default**: `20s`

#### skip-files

Indicates whether file scanning is enabled. This affects the scan triggered by the image loading, create file, and file mapping operations.

**default**: `false`

#### skip-allocs

Indicates whether scanning on suspicious memory allocations is disabled.

**default**: `false`

#### skip-mmaps

Indicates whether scanning on suspicious mappings of sections is disabled.

**default**: `false`


#### skip-registry

Indicates whether registry value scanning is disabled.

**default**: `false`


#### excluded-files

Contains the list of the comma-separated file paths that shouldn't be scanned. Wildcard matching is possible. For example:

```
excluded-files:
	- ?:\\Windows\\System32\\kernel32.dll
```

#### excluded-procs

Contains the list of the comma-separated process image paths that shouldn't be scanned. Wildcard matching is possible.
