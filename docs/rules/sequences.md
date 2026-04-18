# Sequences

##### In a nutshell, **sequence rules** allow to model behaviors that unfold over time by tracking an **ordered chain of events**. Instead of matching a single event in isolation, sequences let you express *causality* - "this happened, and then shortly after, that happened".

A sequence rule always starts with the `sequence` keyword and is composed of **two or more expressions** separated by vertical bars (`|`). Each expression represents a step in the behavioral chain.

A match occurs only if:

1. All expressions evaluate to `true`
2. They do so in the declared order
3. They occur within the allowed time window (if specified)

Let’s revisit a real-world example:

```yaml
condition: >
  sequence
  maxspan 2m
  by ps.uuid
    |open_process and
     ps.access.mask.names in ('ALL_ACCESS', 'CREATE_PROCESS', 'VM_READ') and
     evt.arg[exe] imatches '?:\\Windows\\System32\\lsass.exe' and
     ps.exe not imatches
            (
              '?:\\Windows\\System32\\svchost.exe',
              '?:\\ProgramData\\Microsoft\\Windows Defender\\*\\MsMpEng.exe'
            )
    |
    |create_new_file and file.extension iin ('.dmp', '.mdmp', '.dump')|
```

### How this sequence works

This rule detects a classic LSASS memory dump pattern:

1. A process opens a handle to `lsass.exe` with suspicious access rights
2. The same process writes a minidump file shortly after

This is a strong behavioral signal because **neither event alone is necessarily malicious**, but their combination in sequence is.

---

## Execution model (important mental model)

A sequence behaves like a **state machine**:

* Each incoming event is evaluated against the **current stage(s)** of active sequences
* When the first expression matches, a new sequence instance is created
* That instance waits for the next expression to match
* If all expressions match in order → **sequence fires**
* If constraints (like time) are violated → **sequence is discarded**

Multiple sequence instances can exist concurrently for different processes or entities.

---

## Controlling sequence behavior

### `maxspan`

`maxspan` defines the **maximum time allowed between the first and last expression** in the sequence.

```yaml
maxspan 2m
```

* Supported units: `ms`, `s`, `m`, `h`
* The timer starts **after the first expression matches**
* If the sequence is not completed within this window → it is dropped

**Example:**

* `open_process` matches at `T0`
* `write_minidump_file` must occur before `T0 + 2 minutes`
* Otherwise, the sequence is invalidated

> 💡 Without `maxspan`, sequences can live indefinitely, which is usually undesirable in high-throughput systems.

---

### `by` (event stitching)

The `by` clause ensures that only **related events** participate in the same sequence.

```yaml
by ps.uuid
```

This means:

* All expressions must match events sharing the same `ps.uuid`
* Prevents unrelated events from being incorrectly combined

`ps.uuid` is preferred over `ps.pid` because it is **stable and not subject to PID reuse**.

#### Per-expression `by`

You can also define **different join keys per step**:

```yaml
sequence
maxspan 1h
  |write_file
      and
   file.extension iin executable_extensions
      and
   ps.name iin msoffice_binaries
  | by file.name
  |spawn_process
      and
   ps.name iin msoffice_binaries
  | by ps.child.exe
```

Here:

* First step groups by `file.name`
* Second step groups by `ps.child.exe`

👉 This effectively expresses:

> “The file that was written must be the same file that gets executed later.”

This pattern is extremely powerful for modeling **dropper → execution chains**.

---

### Omitting `by` and `maxspan`

Both are optional, but:

* Without `by` → events are correlated globally (high risk of false positives)
* Without `maxspan` → sequences may accumulate indefinitely

Such configurations are rarely useful for precise behavioral detection and are typically reserved for **loose temporal correlations**.

---

## Aliases (`as`) and bound fields

Sometimes, simple equality joins (`by`) are not enough. You may need to:

* Compare values across steps
* Perform transformations
* Match against derived data

This is where **aliases** come in.

### Defining an alias

```yaml
|create_file
  and
 file.name imatches '?:\\Windows\\System32\\*.dll'
| as e1
```

* The matching event is stored as alias `e1`
* It becomes accessible in subsequent expressions

---

### Using bound fields

Bound fields let you reference values from previous steps:

```yaml
$e1.file.name
```

This retrieves the `file.name` from the event captured in `e1`.

---

### Example: DLL persistence via LSA

```yaml
sequence
maxspan 5m
  |create_file
      and
   file.name imatches '?:\\Windows\\System32\\*.dll'
  | as e1
  |modify_registry
      and
   registry.key.name ~= 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages'
      and
   get_reg_value(registry.key.name) iin (base($e1.file.name, false))
  |
```

### What’s happening here

1. A DLL is dropped into `System32`
2. That DLL name is captured as `e1.file.name`
3. A registry value is modified
4. The rule checks whether the registry value contains the **same DLL name**

This is not achievable with `by` alone because:

* The relationship is not simple equality between fields
* It requires **runtime value extraction and comparison**

---

## When to use sequences

Sequences are ideal for detecting:

* Multi-step attacks (e.g., *initial access → execution → persistence*)
* Living-off-the-land techniques
* Cases where **individual events are benign but their combination is not**

### Good candidates

* Credential dumping chains
* File drop → execution
* Registry modification after binary creation
* Parent/child process anomalies over time

### Poor candidates

* Single-event detections (use plain filters instead)
* High-frequency noisy signals without strong correlation keys

---

## Practical tips

* Prefer **short `maxspan` windows** to reduce noise
* Always use a **strong `by` key** (e.g., `ps.uuid`, file path, etc.)
* Use **aliases sparingly but deliberately** for complex relationships
* Think in terms of **attack steps**, not individual events

---

If you want, I can also add a section on **sequence performance characteristics and internal buffering**, which is usually very relevant for Fibratus users operating at scale.



In a nutshell, sequences permit state tracking of an ordered series of events over a short period of time. Let's peer into the structure of sequence-powered rules. Sequence rules start with the `sequence` keyword as you can observe in the `LSASS memory dumping via legitimate or offensive tools` rule's condition. Sequence consists of two or more expressions surrounded by vertical bars or pipes. For the sequence to match, all expressions need to match successively in time.

```yaml
name: LSASS memory dumping via legitimate or offensive tools
id: 335795af-246b-483e-8657-09a30c102e63
version: 1.0.0
description: |
  Detects an attempt to dump the LSAAS memory to the disk by employing legitimate
  tools such as procdump, Task Manager, Process Explorer or built-in Windows tools
  such as comsvcs.dll.
labels:
  tactic.id: TA0006
  tactic.name: Credential Access
  tactic.ref: https://attack.mitre.org/tactics/TA0006/
  technique.id: T1003
  technique.name: OS Credential Dumping
  technique.ref: https://attack.mitre.org/techniques/T1003/
  subtechnique.id: T1003.001
  subtechnique.name: LSASS Memory
  subtechnique.ref: https://attack.mitre.org/techniques/T1003/001/
references:
  - https://redcanary.com/threat-detection-report/techniques/lsass-memory/
  - https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before

condition: >
  sequence
  maxspan 2m
  by ps.uuid
    |open_process
      and
     ps.access.mask.names in ('ALL_ACCESS', 'CREATE_PROCESS', 'VM_READ')
      and
     kevt.arg[exe] imatches '?:\\Windows\\System32\\lsass.exe'
      and
      not
     ps.exe imatches
      (
        '?:\\Windows\\System32\\svchost.exe',
        '?:\\ProgramData\\Microsoft\\Windows Defender\\*\\MsMpEng.exe'
      )
    |
    |write_minidump_file|

output: >
  Detected an attempt by `%1.ps.name` process to access and read
  the memory of the **Local Security And Authority Subsystem Service**
  and subsequently write the `%2.file.name` dump file to the disk device
severity: critical

min-engine-version: 2.0.0
```

The sequence behavior can be controlled by the following statements:

- `maxspan` defines the time window in duration units, such as `2s`, `2m`, or `2h` for two minutes, two hours, and two days respectively. The time window dictates how long each expression in the sequence is expecting to wait for events that could result in expression evaluating to true. For example, by examining the above snippet, the sequence starts by detecting process handle acquisition on the `lsass` process. Since this is the first expression in the sequence, the time window constraint doesn't kick in yet. After the first expression evaluates to true, the next one, expecting to detect creation of the minidump file, will evaluate only if the `CreateFile` event arrives within the 2 minutes time frame. Otherwise, the deadline is reached and the entire sequence is discarded.
- `by` enables event stitching by any of the [filter fields](filters/fields). It guarantees that only events sharing certain properties will be eligible for matching. Continuing the example from previous rule, the sequence can match only if `OpenProcess` and `CreateFile` events are generated by the same process. Specifically, events are joined by the `ps.uuid` field which is meant to offer a more robust version of the `ps.pid` field that is resistant to being repeated. A variation of the `by` statement allows establishing a joining criteria separately on each expression in the sequence. Let's take a look at the following rule:

```yaml
sequence
maxspan 1h
  |write_file
      and
   file.extension iin executable_extensions
      and
   ps.name iin msoffice_binaries
  | by file.name
  |spawn_process
      and
   ps.name iin msoffice_binaries
  | by ps.child.exe
```

As we can observe, the `by` statement is anchored to each expression but using a different join field. This rule would only match if the file being written is equal to the spawned process executable image.
Of course, it is possible to omit both `maxspan` and `by` statements. However, such rules are rarely used to express behaviors that require relationships between events, instead, a mere temporally connection.

#### Aliases

In certain situations, expressing event stitching relations may require more complex heuristics. Imagine a detection rule checking the presence of a created filename against the list of values obtained in subsequent sequence expression. An avid reader may immediately realize this sort of joining is not attainable by means of the `by` statement. Luckily, a more flexible solution exists in form of the `as` statement. This statement allows creating aliases which can be referenced in sequence expressions by using **bound fields**. Bound field is essentially a regular filter field prefixed with an alias. Let's see another example.

```yaml
sequence
maxspan 5m
  |create_file
      and
   file.name imatches '?:\\Windows\\System32\\*.dll'
  | as e1
  |modify_registry
      and
   registry.key.name ~= 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Notification Packages'
      and
   get_reg_value(registry.key.name) iin (base($e1.file.name, false))
  |
```

The first expression in the sequence detects the creation of a DLL file in the system directory. Once this expression evaluates to true, the event that triggered it is accessible via the `e1` alias. The second expression will detect registry modifications on the specified value, and if eligible, it will use the `get_reg_value` function to query the value, which, in this case,contains the `MULTI_SZ` content. The retrieved list of strings is compared against the filename from the event matching the first expression. The `$e1.file.name` bound field is responsible for consulting the filename field value from the referenced expression's matching event.