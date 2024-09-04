# Rules

Rules bring a set of capabilities for detecting and disrupting the adversary kill chain exploiting stealthy attacks and advanced threat models. Fibratus comes equipped with a decent catalog of [detection rules](https://github.com/rabbitstack/fibratus/tree/master/rules) built on top of the [MITRE ATT&CK](https://attack.mitre.org/) framework with each rule mapped to the most relevant tactics, techniques, and sub-techniques.

Detection rules are organized in `yaml` files. Rules can live in different directories and there is no strict naming convention. However, the recommended practice is to follow the `tactic_name_rule_name.yml` naming nomenclature. Analysts are encouraged to follow design guidelines to produce optimal rules.

#### Stick to naming nomenclature {docsify-ignore}

It is highly recommended to name the rule files after the pattern explained in the above section. This facilitates the organization and searching through the detection rules catalog and fosters standardization.

#### Include descriptions and labels {docsify-ignore}

Rules should have a meaningful description.
For example, `Potential process injection via tainted memory section`.

Additionally, there should exist labels attached to every rule describing the MITRE tactic, technique, and sub-technique. This information is used when rendering email rule alert templates as depicted in the image above.

#### Rules should have a narrowed event scope {docsify-ignore}

If a rule is declared without the scoped event conditions, such as `kevt.name` or `kevt.category`, you'll get a warning message in `Fibratus` logs informing you about unwanted side effects. **This always lead to the rule being utterly discarded by the engine!**

#### Pay attention to the condition arrangement {docsify-ignore}

As highlighted in the previous paragraph, all rules should have the event type condition. Additionally, condition arrangement may have important runtime performance impact because the rule engine can lazily evaluate binary expressions that comprise a rule. In general, costly evaluations or functions such as `get_reg_value` should go last to make sure they are evaluated after all other expressions have been visited.

#### Prefer macros over raw conditions {docsify-ignore}

Fibratus comes with a [macros](https://www.fibratus.io/#/filters/rules?id=macros) library to promote the reusability and modularization of rule conditions and lists. Before trying to spell out a raw rule condition, explore the library to check if there's already a macro you can pull into the rule. For example, detecting file accesses could be accomplished by declaring the `kevt.name = 'CreateFile' and file.operation = 'open'` expression. However, the macro library comes with the `open_file` macro that you can directly call in any rule. If you can't encounter a particular macro in the library, please consider creating it. Future detection engineers and rule writers could profit from those macros.

#### Formatting styles {docsify-ignore}

Pay attention to rule condition/action formatting style. If the rule consists of multiple or large expressions, it is desirable to split each spanning expression on a new line and properly indent the `and`, `or`, or `not` operators. By default, we use 1 space tab for indenting operators and rule actions. This notably improves readability and prevents formatting inconsistencies.

### Loading rules

By default, rules reside inside `%PROGRAM FILES%\Fibratus\Rules` directory. You can load any number of rule files from file system paths or URL locations. It is possible to utilize the wildcard expressions in file paths to enumerate multiple rule files from a single path specifier.

Edit the main [configuration](/setup/configuration?id=files) file. Go to the `filters` section where the following `yaml` fragment is located:

```yaml
filters:
  rules:
    from-paths:
      - C:\Program Files\Fibratus\Rules\*.yml
    from-urls:
      - https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_unusual_access_to_windows_credential_history.yml
```

- `from-paths` represents an array of file system paths pointing to the rule definition files
- `from-urls` is an array of URL resources that serve the rule definitions

### Creating rules

Let's have a glimpse at an example of a simple rule definition described in `yaml` format. When creating a new rule, use the `fibratus rules create` CLI command. It will create a `yaml` template with some required fields populated automatically. Run `fibratus rules create -h` to get extended help on this command.

```yaml
name: Unusual access to Windows Credential history files
id: 9d94062f-2cf3-407c-bd65-4072fe4b167f
version: 1.0.0
description: |
  Detects unusual accesses to the Windows Credential history file.
  The CREDHIST file contains all previous password-linked master key hashes used by
  DPAPI to protect secrets on the device. Adversaries may obtain credentials
  from the Windows Credentials Manager.
enabled: true
labels:
  tactic.id: TA0006
  tactic.name: Credential Access
  tactic.ref: https://attack.mitre.org/tactics/TA0006/
  technique.id: T1555
  technique.name: Credentials from Password Stores
  technique.ref: https://attack.mitre.org/techniques/T1555/
  subtechnique.id: T1555.004
  subtechnique.name: Windows Credential Manager
  subtechnique.ref: https://attack.mitre.org/techniques/T1555/004/
tags:
  - credential stealing
references:
  - https://www.passcape.com/windows_password_recovery_dpapi_credhist

condition: >
  open_file
    and
  file.name imatches '?:\\Users\\*\\AppData\\*\\Microsoft\\Protect\\CREDHIST'
    and
    not
  ps.exe imatches
    (
      '?:\\Program Files\\*',
      '?:\\Windows\\System32\\lsass.exe',
      '?:\\Windows\\System32\\svchost.exe',
      '?:\\Windows\\ccmcache\\*.exe'
    )

output: |
  Detected an attempt by `%ps.name` process to access and read
  Windows Credential history file at `%file.name`
severity: critical

action:
  - name: kill

min-engine-version: 2.0.0

notes: |
  Anything else relevant for the analyst.
```

1. `name` (required). Short title to emphasize rule's intent. The rule name is primary message used in security alerts.
2. `id` (required). Anchors a unique identifier to the rule that never changes, while the name could change over time.
3. `version` (required). Describes the rule version. The version is useful to track regressions or breaking changes.
4. `description` (optional). A larger explanation of what the rule should detect. Provide as much context as possible to the analyst.
5. `enabled` (optional). Sometimes it comes in handy to temporarily disable a specific rule. If omitted, the default value is `true`.
6. `labels` (optional). Arbitrary key/value pairs. As per [best practices](https://github.com/rabbitstack/fibratus/tree/master/rules#guidelines) rule design guidelines, it is highly recommended to include labels for the MITRE tactic, technique/sub-technique. Of course, you are free to populate the labels attribute with any other useful data.
7. `tags` (optional). Unlike labels, tags represent a sequence of meaningful keywords that you may find useful for categorization purposes.
8. `references` (optional). List of web resources, documents, etc. with relevant information about adversary tactics, defensive strategy, and so on.
9. `condition` (required). Well-known filter expression we used to employ in the CLI filters. You might have spotted some additional constructs like `open_file`. They are called macros, and we'll dive into macros goodies in the next section.
11. `output` (optional) Provides additional context in the alert description. It is possible to use fields interpolation, as seen later.
12. `severity` (optional) Sets the alert severity. Possible values are `low`, `medium`, `high`, and `critical`. If omitted, `medium` severity is assumed.
13. `action` (optional) Rule action can perform a variety of operations, such killing a process involved in the matched rule condition.
14. `min-engine-version` (required) Identifies the minimum Fibratus version that is compatible with the rule.
15. `notes` (optional). Any notes or observations that you would like to communicate to the analyst.

#### Macros

Macros foment rule patterns reusability and a human-friendly domain-specific language (DSL). A vast majority of detection rules may require conditions to express process execution or file writes. Traditionally, one could spell out a raw filter expression such as `kevt.name = 'CreateProcess'`. This may lead to bloated and boilerplate rules. From the maintenance standpoint, introducing a small change in the rule condition would force us to update all the rules, while macros are a much more convenient mechanism for declaring reusable rule patterns. Fibratus ships with a [macros library](https://github.com/rabbitstack/fibratus/blob/master/rules/macros/macros.yml) containing a dozen of different macros ready to use. Macros library is loaded from the file system and can be split across multiple `yaml` files. The default location is designated by the `%PROGRAM FILES%\Fibratus\Rules\Macros` directory.

```yaml
filters:
  macros:
    from-paths:
      - C:\Program Files\Fibratus\Rules\Macros\*.yml
```

Macros come in two flavors:

- **expression** macros encapsulate filter expressions. A macro declaration requires a unique macro name, the filter expression, and an optional description.

```yaml
- macro: spawn_process
  expr: kevt.name = 'CreateProcess'
  description: Identifies the execution of a new process
```

Where macro expressions really shine is when combined with other macros to forge recursive macros. For example, the `spawn_msoffice_process` is composed of `spawn_process` expression macro and the `msoffice_binaries` list macro.

```yaml
- macro: spawn_msoffice_process
  expr: spawn_process and ps.sibling.exe iin msoffice_binaries
  description: Identifies the execution of the MS Office process
```

- **list** macros declare a sequence of items such as file system paths, process names, or registry keys. List macros help to make the rules succinct and clean. An example of a macro list containing Microsoft Office process image names. Various operators, such as `in`, `matches`, or `startswith` can accept list macros as RHS (Right Hand Side) expressions.

```yaml
- macro: msoffice_binaries
  list: [EXCEL.EXE, WINWORD.EXE, MSACCESS.EXE, POWERPNT.EXE]
```

#### Templates {docsify-ignore}

Both, rule and macro `yaml` files can include Go [template](https://pkg.go.dev/text/template) directives. This encompasses loops, conditional directives, pipelines, or functions. Fibratus ships with a collection of [predefined](http://masterminds.github.io/sprig/) functions for string and filepath manipulation, math, date, and cryptographic functions to name a few. 

To illustrate the use of templates, let's assume the rules we deploy should require a minimum engine version of `2.0.0` under the presence of a certain environment variable in the host. By combining different Go template directives, we can conditionally render a fragment of the `yaml` file if the `env` function which receives the `AZ` environment variable name returns the `za` value.

```yaml
name: Execution via Microsoft Office process
id: a10ebe66-1b55-4005-a374-840f1e2933a3
version: 1.0.0
description:
  Identifies the execution of the file dropped by Microsoft Office process.
labels:
  tactic.id: TA0001
  tactic.name: Initial Access
  tactic.ref: https://attack.mitre.org/tactics/TA0001/
  technique.id: T1566
  technique.name: Phishing
  technique.ref: https://attack.mitre.org/techniques/T1566/
  subtechnique.id: T1566.001
  subtechnique.name: Spearphishing Attachment
  subtechnique.ref: https://attack.mitre.org/techniques/T1566/001/

condition: >
  sequence
  maxspan 1h
    |create_file
      and
     (file.extension iin executable_extensions or file.is_exec)
      and
     ps.name iin msoffice_binaries
    | by file.name
    |spawn_process
      and
     ps.name iin msoffice_binaries
    | by ps.child.exe

{{- if eq (env "AZ") "za" }}
min-engine-version: 2.0.0
{{- else }}
min-engine-version: 2.2.0
{{- end }}
```

### Actions

Actions are responses executed as a consequence of rule matches. Actions provide alerting and prevention capabilities aim at stopping the adversary at the initial stages of the attack.

#### Generating alerts

Alerts are automatically generated when the rule matches. The alert is sent via all active [senders](/alerts/senders). [Systray](/alerts/senders/systray) alert sender is enabled by default. The rule name is used in the alert title. To provide extra context in the alert, the rule `output` attribute can be used in combination with **field interpolation**. In the following snippet, we use the `%ps.exe` format modifier to render the process executable path. Formats modifiers are well-known filter fields prefixed with the `%` symbol. 

```yaml
output: |
  "%ps.exe process spawned a command shell after connecting to the remote endpoint
```

In the case of sequence rules, we can access the desired event reference by including the ordinal which points to the slot in the sequence. This way, `%1.ps.name` would yield the name of the process in the first sequence slot, while `%2.file.name` gives us the filename located in the event reference of the second slot. Both, title and text permit including Markdown or HTML tags.

```yaml
output: |
  Detected an attempt by <code>%1.ps.name</code> process to access
  and read the memory of the **Local Security And Authority Subsystem Service**
  and subsequently write the <code>%2.file.name</code> dump file to the disk device
```

[email](alerts/senders/mail.md) alert senders render beautiful responsive HTML emails as depicted in the image below. Email rule alerts deliver high-fidelity and incident-centric notifications that aim to prevent alert fatigue by summarizing key investigation insights.

<p align="center">
  <img src="filters/images/rule-alert.png"/>
</p>

The email alerts have the following sections:

- Date, time, and the hostname where the alert was triggered
- Alert severity given by the `severity` attribute
- Alert title as specified the `name` attribute
- Alert description as specified by the `output` attribute
- Links with MITRE tactic, technique, and sub-technique
- The list of security events involved in the incident. For each event, the name, timestamp, and excerpt are shown. Next, all event attributes and process state information is represented.

#### Killing processes

`kill` action terminates the process involved in matched rule condition. Fibratus needs to acquire the process handle with the `PROCESS_TERMINATE` access rights to successfully kill the process.

```yaml
action:
  - name: kill
```

### Advanced patterns

Adversaries often employ sophisticated techniques which may be daunting to detect without combining events from different data sources. For example, detecting a remote connection attempt followed by the execution of a command shell by the same process that initiated the connection can't be expressed with a simple rule expecting to match on a single event. Enter `sequence` rules.

#### Sequences

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
