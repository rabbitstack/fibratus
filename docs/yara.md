# Memory Scanning

Here’s a clearer, more structured, and expanded version of your **YARA / Memory Scanning** documentation, with improved flow and additional technical depth.

---

# Memory scanning (YARA)

YARA is a widely adopted framework for **binary pattern matching and malware classification**. It allows you to define rules that describe suspicious or malicious artifacts based on strings, byte patterns, and structural properties.

Fibratus integrates YARA directly into its event processing pipeline to enable **real-time and replay-based scanning of memory and binaries**.

---

## Overview

The Fibratus–YARA integration focuses on detecting:

* **In-memory threats** (fileless malware, injected code)
* **Suspicious PE artifacts** (executables, DLLs, drivers)
* **Abnormal memory behavior**

Unlike traditional file-based scanning, this approach allows visibility into **runtime activity**, which is crucial for modern attack techniques.

---

## How it works

Fibratus embeds **`libyara`** via native bindings:

* The YARA engine is **statically linked**
* No additional installation is required
* Rules are compiled and executed inside the Fibratus runtime

Scanning is triggered by **specific system events**, allowing Fibratus to analyze relevant memory regions or binaries at the right time.

---

## Detection signals

Fibratus invokes YARA scanning in response to high-value behavioral signals, including:

### Process and image activity

* New process creation
* Loading of executables or DLLs
* Loading of **unsigned or untrusted modules**
* Execution from **unbacked (non-file-backed) memory regions**

---

### File system activity

* Creation of PE files (`.exe`, `.dll`, `.sys`)
* Creation of files in suspicious locations
* Creation of **Alternate Data Streams (ADS)**

---

### Memory behavior

* Allocation of **RWX (Read-Write-Execute)** memory regions
* Mapping of suspicious memory sections
* Indicators of code injection or shellcode presence

---

### Registry activity

* Writing of **binary registry values** that may contain payloads

---

## Why this matters

Modern malware increasingly avoids writing artifacts to disk. Instead, it:

* Injects code into legitimate processes
* Executes payloads directly from memory
* Uses obscure persistence mechanisms

YARA scanning in Fibratus helps detect these techniques by:

* Inspecting memory at runtime
* Correlating behavioral signals with content analysis
* Applying signature-based detection to transient artifacts

---

## Enabling YARA scanning

YARA scanning is **disabled by default**.

To enable it, update the configuration:

```yaml id="9t9n6y"
yara:
  enabled: true
```

Once enabled, Fibratus will:

* Load configured YARA rules
* Monitor triggering events
* Scan relevant memory regions and binaries

---

## Writing and using YARA rules

YARA rules define what constitutes suspicious content. A simple example:

```yara id="v5k3qa"
rule SuspiciousString {
  strings:
    $a = "mimikatz"
  condition:
    $a
}
```

These rules can match:

* Raw byte sequences
* ASCII/Unicode strings
* Complex logical conditions

> 💡 YARA rules operate independently of Fibratus filters and can complement rule-based detections.

---

## Integration with Fibratus workflows

YARA works seamlessly alongside other Fibratus features:

### With rules

* Use rules to detect suspicious behavior
* Use YARA to confirm malicious content

---

### With captures

* Replay `.kcap` files and apply YARA retroactively
* Analyze historical activity with updated signatures

---

### With filaments

* Trigger custom logic when YARA matches occur
* Enrich or export detection results

---

## Performance considerations

YARA scanning is powerful but not free:

* Memory scanning can be **CPU-intensive**
* Large rule sets may impact performance
* Frequent triggering events increase scanning load

### Recommendations

* Use **targeted rule sets** instead of large generic ones
* Combine with filters to reduce unnecessary scans
* Monitor performance in high-throughput environments

---

## Best practices

* Focus on **high-signal YARA rules** (avoid overly generic patterns)
* Combine behavioral detection (rules/sequences) with YARA validation
* Regularly update rule sets with new threat intelligence
* Test rules against **capture replays** before enabling in production

---

## Summary

The Fibratus–YARA integration brings **content-based detection** into a **behavioral monitoring system**, enabling:

* Detection of fileless and in-memory threats
* Deep inspection of runtime artifacts
* Stronger, layered detection strategies

By combining **event-driven signals** with **pattern matching**, Fibratus provides a powerful mechanism to uncover threats that would otherwise remain invisible.

---

If you want, I can also add a section on **how Fibratus selects memory regions for scanning (address space, sections, protections)** or a **real-world YARA + sequence rule combo example**, which is often very useful in practice.


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

# Scanning Processes

For the YARA scanner to operate correctly, the rules have to be compiled and loaded into the engine. This is accomplished by providing file system paths with YARA rule definitions in the `rule.paths` configuration keys. The directories are scanned recursively for any `.yar` file. Alternatively, it is possible to provide the rules as inline strings directly in the Fibratus configuration file.

### Configuration 

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

# Alerts

Alerts on rule matches are automatically sent via all active alert senders.

##  Event metadata 

When the event triggers a specific YARA rule, its metadata is automatically decorated with the rule matches. 
The `yara.matches` tag contains the JSON array payload where each object represents the YARA rule match. For example:

```json
[
  {
    "rule": "AnglerEKredirector ",
    "namespace": "EK",
    "tags": null,
    "metas": [
      {
        "identifier": "description",
        "value": "Angler Exploit Kit Redirector"
      }
    ],
    "strings": "..."
  },
  {
    "rule": "angler_flash_uncompressed ",
    "namespace": "EK",
    "tags": [
      "exploitkit"
    ],
    "metas": [
      {
        "identifier": "description",
        "value": "Angler Exploit Kit Detection"
      }
    ],
    "strings": "..."
  }
]
```
