# Rules

Rules bring a set of capabilities for detecting and disrupting the adversary kill chain exploiting stealthy attacks and advanced threat models. Fibratus comes equipped with a decent catalog of [detection rules](https://github.com/rabbitstack/fibratus/tree/master/rules) built on top of the [MITRE ATT&CK](https://attack.mitre.org/) framework with each rule mapped to the most relevant tactics, techniques, and sub-techniques.
In a nutshell, rules are a collection of grouped filters defined in `yaml` files. Specifically, the following attributes describe a rule group:

- **name** associates a meaningful name to the group such as `Suspicious network-connecting binaries`
- **description** represents a detailed explanation of the rule group. 
- **labels** are arbitrary key/value pairs. As per [best practices](https://github.com/rabbitstack/fibratus/tree/master/rules#guidelines) rule design guidelines, it is highly recommended to include labels for the MITRE tactic, technique/sub-technique. Of course, you are free to populate the labels attribute with any other useful data.
- **tags**, unlike labels, tags represent a sequence of meaningful keywords that you may find useful for categorization purposes.
- **enabled** specifies whether the rules in the group are susceptible for matching.
- **policy** determines how the rule engine will react on rule matching. There are two types of policies: `include` and `exclude` policies. Include policies permit executing an action when the rule matches in addition to propagating the event to the output sink. Exclude policies will simply discard the event matching any of the rules in the group.
- **relation** controls the group matching criteria. Possible values for the group relation are `and` and `or`. When the `and` relation type is specified, all rules in the group have to match to retain the event. The actions are executed for every individual rule. Conversely, the `or` relation type requires at least one rule in the group to evaluate to true for the rule action to execute and propagate the event to the output. 
- **rules** contains an array of rule expressions. Each expression is composed of a descriptive rule name, condition, and an action that is executed when the rule is triggered.

### Loading rules

By default, rules reside inside `%PROGRAM FILES%\Fibratus\Rules` directory. You can load any number of rule files from file system paths or URL locations. It is possible to utilize the wildcard expressions in file paths to enumerate multiple rule files from a single path specifier.

Edit the main [configuration](/setup/configuration?id=files) file. Go to the `filters` section where the following `yaml` fragment is located:

```yaml
filters:
  rules:
    from-paths:
      - C:\Program Files\Fibratus\Rules\*.yml
    from-urls:
      - https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_credentials_from_password_stores.yml
```

- `from-paths` represents an array of file system paths pointing to the rule definition files
- `from-urls` is an array of URL resources that serve the rule definitions

### Defining rules

As mentioned previously, rules are bound to groups. Let's have a glimpse at an example of a group with two rules.

```yaml
- group: Credentials access from Windows Credential Manager
  description: |
    Adversaries may acquire credentials from the Windows Credential Manager.
    The Credential Manager stores credentials for signing into websites,
    applications, and/or devices that request authentication through NTLM
    or Kerberos in Credential Lockers.
  enabled: true
  policy: include
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
  rules:
    - name: Unusual process accessing Windows Credential history
      description: |
        Detects unusual accesses to the Windows Credential history file.
        The CREDHIST file contains all previous password-linked master key hashes used by
        DPAPI to protect secrets on the device. Adversaries may obtain credentials
        from the Windows Credentials Manager.
      condition: >
        open_file
            and
        file.name imatches '?:\\Users\\*\\AppData\\*\\Microsoft\\Protect'
            and
            not
        ps.exe imatches
            (
              '?:\\Program Files\\*',
              '?:\\Windows\\System32\\svchost.exe'
            )
      action: >
        {{
            emit . "Unusual access to Windows Credential history files" ""
        }}
    - name: Enumerate credentials from Windows Credentials Manager via VaultCmd.exe
      description: |
        Detects the usage of the VaultCmd tool to list Windows Credentials.
        VaultCmd creates, displays and deletes stored credentials.
      condition: >
        spawn_process
            and
        ps.sibling.name ~= 'VaultCmd.exe'
            and
        ps.sibling.args
            in
          (
            '"/listcreds:Windows Credentials"',
            '"/listcreds:Web Credentials"'
          )
      action: >
        {{
            emit
              .
            "Credential discovery via VaultCmd.exe"
            "`%ps.exe` executed the `VaultCmd` tool to enumerate Windows Credentials"
        }}
  tags:
    - Credential Access
    - Windows Credential Manager
```

1. The group needs a mandatory name. You can define as many groups as you like. Group names must be unique for the same policy type.

2. Sometimes it comes in handy to temporarily disable a specific group. This is the purpose of the `enabled` attribute. It can be omitted and by default it is equal to `true`.

3. Each group is tied to a policy. Group policy determines how the matching rule reacts on behalf of the event. `exclude` policies drop the event which activated the rule inside the group. The `exclude` policy prevents the propagation of the event towards the [output](/outputs/introduction) sinks. Also, no rule actions are triggered in `exclude` policies. Exclude policies take precedence over other policies. If omitted, `include` is the default policy assigned to the group. `include` policies fire the action defined in each rule in addition to routing the event to the output sink.

4. If we need all the rules in a group to produce a match, we can tune up the `relation` attribute. By default, the `or` relation allows for the group match to get promoted if a single rule in a group is evaluated to be true. On the contrary, the `and` relation type would instruct the rule engine to promote the match only if all rules are matched. 

5. The collection of rules is specified in the `rules` attribute. You may notice the `condition` element contains the well-known filter expression we used to employ in the CLI filters. You might have spotted some additional constructs like `open_file` or `spawn_process`. They are called macros, and we'll dive into macros goodies in the next section. Each rule may have an action which is executed when the rule is matched against the event. Rule action can perform a variety of operations, such as generating an alert or killing a process.


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

To illustrate the use of templates, let's assume the rules we deploy should only be enabled under the presence of a certain environment variable in the host. By combining different Go template directives, we can conditionally render a fragment of the `yaml` file if the `env` function which receives the `AZ` environment variable name returns the `za` value.

```yaml
- group: Spearphishing DLL attachment loaded by Microsoft Office processes
  description: |
    Adversaries may send spearphishing emails with a malicious attachment in an
    attempt to gain access to victim systems. Identifes the creation of the DLL
    which is loaded by Microsoft Office process afterwards. May indicate loading of
    a possibly malicious module.
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
  policy: sequence
{{- if eq (env "AZ") "za" }}
  rules:
    - name: Potentially malicious module loaded by Microsoft Office process
      condition: >
        sequence
        maxspan 1h
          |write_file
              and
           file.extension iin module_extensions
              and
           ps.name iin msoffice_binaries
          | by file.name
          |load_module
              and
           ps.name iin msoffice_binaries
          | by image.name
      action: >
        {{
            emit . "Potentially malicious module loaded by Microsoft Office process" ""
        }}
{{- end }}
```

### Actions

Actions are responses executed as a consequence of rule matches. Actions provide alerting and prevention capabilities aim at stopping the adversary at the initial stages of the attack. The action must be a valid Go template block. Unlike templates, which are evaluated at rule load time, action blocks are evaluated when the rule fires. All action blocks have access to the root context consisting of the following fields:

- `.Kevt` accesses the underlying event that triggered the rule. Refer to this [link](https://github.com/rabbitstack/fibratus/blob/83cd37820b208846809f82b19e857bff6f4eb415/pkg/kevent/kevent.go#L55) to inspect all possible subfields. 
For sequences, which are explained in the [Advanced patterns](filters/rules?id=advanced-patterns) section, a list of all matched events is given instead. Thus, accessing a matching event for the specific group is accomplished with the `.Kevts.k{sequence-slot}` expression. For example, to access the process name of the event that matched the expression in the first sequence slot, you would use `.Kevts.k1.PS.Name`. Fields interpolation, which is explained in the next section, allows a more convenient and succinct way to access event fields.
- `.Filter` provides access to filter attributes. The following subfields are available:
    - `.Filter.Name` gets the filter/rule name
    - `.Filter.Condition` gets the filter expression
- `.Group` provides access to group attributes. The following subfields are available:
    - `.Group.Name` gets the group name
    - `.Group.Policy` returns the group policy
    - `.Group.Relation` returns the group relation
    - `.Group.Tags` fetches the group tags

Rule and group information is also pushed into the event metadata stitching the rule with the event that triggered it. `rule.name` and `rule.group` tags identify the rule and the group name respectively. For example, you can configure the console output [template](outputs/console?id=templates) to print the metadata of the event. Similarly, other outputs will produce the corresponding JSON dictionary with the rule tags.

#### Generating alerts

- The `emit` action sends an alert via alert [senders](/alerts/senders). The `emit` action requires a title, alert detailed description, and optionally, the severity level and a list of tags attached to the alert. The first argument to the `emit` must be the root action context represented by the `.` symbol. Let's see some examples.

```yaml
action: >
    {{ 
        emit
          . 
        "Command shell spawned after remote connection"
        (printf "%s process spawned a command shell after connecting to the remote endpoint" .Kevt.PS.Exe)
        "critical"
    }}
```

The above action sends the alert with the given title, description, and `critical` severity. If omitted, the `medium` severity level is set instead. As you may notice, the `printf` function from the standard Go template library is used to concatenate the full executable path of the process spawning a command shell. Instead of accessing raw event fields, we can resort to **field interpolation**. In the following snippet, we use the `%ps.exe` format modifier to render the process' executable path. Formats modifiers are well-known filter fields prefixed with the `%` symbol. 

```yaml
action: >
    {{ 
        emit
          . 
        "Command shell spawned after remote connection"
        "%ps.exe process spawned a command shell after connecting to the remote endpoint"
        "critical"
    }}
```
In the case of sequence rules, we can access the desired event reference by including the ordinal which points to the slot in the sequence. This way, `%1.ps.name` would yield the name of the process in the first sequence slot, while `%2.file.name` gives us the filename located in the event reference of the second slot. Both, title and text permit including Markdown or HTML tags.

```yaml
action: >
    {{
        emit
          .
        "LSASS memory dumping"
        `Detected an attempt by <code>%1.ps.name</code> process to access
         and read the memory of the **Local Security And Authority Subsystem Service**
         and subsequently write the <code>%2.file.name</code> dump file to the disk device `
        "critical"
    }}
```

[email](alerts/senders/mail.md) alert senders render beautiful responsive HTML emails as depicted in the image below. Email rule alerts deliver high-fidelity and incident-centric notifications that aim to prevent alert fatigue by summarizing key investigation insights.

<p align="center">
  <img src="filters/images/rule-alert.png"/>
</p>

The email alerts have the following sections:

- Date, time, and the hostname where the alert was triggered
- Alert severity given in the `emit` action
- Alert title as specified in the `emit` action
- Alert description as specified in the `emit` action
- Links with MITRE tactic, technique, and sub-technique
- Description of the rule group
- The list of security events involved in the incident. For each event, the name, timestamp, and excerpt are shown. Next, all event attributes and process state information is represented.


#### Killing processes

- `kill` action terminates a process with the specified pid. Fibratus needs to acquire the process handle with the `PROCESS_TERMINATE` access rights to successfully kill the process.

```yaml
action: >
    {{ 
        kill .Kevt.PID
    }}
```

### Advanced patterns

Adversaries often employ sophisticated techniques which may be daunting to detect without combining events from different data sources. For example, detecting a remote connection attempt followed by the execution of a command shell by the same process that initiated the connection can't be expressed with a simple rule expecting to match on a single event. Enter `sequence` rules.

#### Sequences

In a nutshell, sequences permit state tracking of an ordered series of events over a short period of time. Let's peer into the structure of sequence-powered rules. Sequence rules start with the `sequence` keyword as you can observe in the `LSASS memory dumping via legitimate or offensive tools` rule's condition. Sequence consists of two or more expressions surrounded by vertical bars or pipes. For the sequence to match, all expressions need to match successively in time.

```yaml
- group: LSASS memory
  rules:
    - name: LSASS memory dumping via legitimate or offensive tools
      description: |
        Detects an attempt to dump the LSAAS memory to the disk by employing legitimate
        tools such as procdump, Task Manager, Process Explorer or built-in Windows tools such
        as comsvcs.dll.
      condition: >
        sequence
        maxspan 2m
        by ps.uuid
          |open_process
              and
           ps.access.mask.names in ('ALL_ACCESS', 'CREATE_PROCESS')
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
      action: >
        {{
            emit
              .
            "LSASS memory dumping"
            `Detected an attempt by <code>%1.ps.name</code> process to access
             and read the memory of the **Local Security And Authority Subsystem Service**
             and subsequently write the <code>%2.file.name</code> dump file to the disk device
            `
            "critical"
        }}
```

The sequence behavior can be controlled by the following statements:

- `maxspan` defines the time window in duration units, such as `2m`, `2h`, or `2d` for two minutes, two hours, and two days respectively. The time window dictates how long each expression in the sequence is expecting to wait for events that could result in expression evaluating to true. For example, by examining the above snippet, the sequence starts by detecting process handle acquisition on the `lsass` process. Since this is the first expression in the sequence, the time window constraint doesn't kick in yet. After the first expression evaluates to true, the next one, expecting to detect creation of the minidump file, will evaluate only if the `WriteFile` event arrives within the 2 minutes time frame. Otherwise, the deadline is reached and the entire sequence is discarded.
- `by` enables event stitching by any of the [filter fields](filters/fields). It guarantees that only events sharing certain properties will be eligible for matching. Continuing the example from previous rule, the sequence can match only if `OpenProcess` and `WriteFile` events are generated by the same process. Specifically, events are joined by the `ps.uuid` field which is meant to offer a more robust version of the `ps.pid` field that is resistant to being repeated. A variation of the `by` statement allows establishing a joining criteria separately on each expression in the sequence. Let's take a look at the following rule:

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
