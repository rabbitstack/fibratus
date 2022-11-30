# Rules

Rules bring a set of capabilities for detecting and disrupting the adversary kill chain exploiting stealthy attacks and advanced threat models. Fibratus comes equipped with a decent catalog of [detection rules](https://github.com/rabbitstack/fibratus/tree/master/rules) built on top of the [MITRE ATT&CK](https://attack.mitre.org/) framework with each rule mapped to the most relevant tactics, techniques, and sub-techniques.
In a nutshell, rules are a collection of grouped filters defined in `yaml` files. Specifically, the following attributes describe a rule group:

- **name** associates a meaningful name to the group such as `Suspicious network-connecting binaries`
- **description** represents a detailed explanation of the rule group. 
- **labels** are arbitrary key/value pairs. As per [best practices](https://github.com/rabbitstack/fibratus/tree/master/rules#guidelines) rule design guidelines, it is highly recommended to include labels for the MITRE tactic, technique/sub-technique. Of course, you are free to populate the labels attribute with any other useful data.
- **tags**, unlike labels, tags represent a sequence of meaningful keywords that you may find useful for categorization purposes.
- **enabled** specifies whether the group is active
- **policy** determines the action that's taken on behalf of the incoming event. There are different types of policies: `include`,  `exclude`, and `sequence.`. Include policy filters the event if one of the filters in the group matches, even though this behavior can be tweaked by setting the `relation` attribute. On the other hand, the exclude policy drops the event when a match occurs in the group.
Sequence policy deserves a [dedicated section](/filters/rules?id=stateful-behaviour). In a nutshell, sequence policy permit stateful event tracking which is the foundation of detections that can assert an ordered sequence of events sharing certain properties.
- **relation** controls the group matching criteria. Possible values for the group relation are `and` and `or`. When the `and` relation type is specified, all filters in the group have to match for the event to get accepted. Conversely, the `or` relation type requires only one filter in the group to evaluate to true for accepting the event. Relation is only relevant for `include` and `exclude` policies.
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

3. Each group must specify a policy. Group policy determines how the matching rule reacts on behalf of the event. `exclude` policies drop the event which activated the rule inside the group. The `exclude` policy prevents the propagation of the event towards the [output](/outputs/introduction) sinks. Also, no rule actions are triggered in `exclude` policies. Exclude policies take precedence over other policies. If omitted, the `include` policy is assigned to the group. `include` policies fire the action defined in each rule in addition to routing the event to the output sink. Lastly, `sequence` policies share some commonalities with `include` policies, but have a more powerful detection capabilities as they may track an ordered sequence of events over a bounded time frame.

4. If we need all the rules in a group to produce a match, we can tune up the `relation` attribute. By default, the `or` relation allows for the group match to get promoted if a single rule in a group is evaluated to be true. On the contrary, the `and` relation type would instruct the rule engine to pass the event only if all rules are matched. This attributes are only valid in the context of `include` and `exclude` group policies.

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
  list: [EXCEL.EXE, WINWORD.EXE, MSACCESS.EXE, POWERPNT.EXE, WORDPAD.EXE]
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
    - name: Module file written by Microsoft Office process
      condition: >
        write_file
            and
        file.extension iin
            (
              '.dll',
              '.ocx',
              '.cpl'
            )
            and
        ps.name iin msoffice_binaries
    - name: Module loaded by Microsoft Office process
      condition: >
        image.name = $1.file.name
            and
        load_module
            and
        ps.name iin msoffice_binaries
      max-span: 1h
  action: >
    {{
        emit . "Potentially malicious module loaded by Microsoft Office process" ""
    }}
{{- end }}
```

### Actions

Actions are responses executed as a consequence of rule matches. Actions provide alerting and prevention capabilities aim at stopping the adversary at the initial stages of the attack. The action must be a valid Go template block. Unlike templates, which are evaluated at rule load time, action blocks are evaluated when the rule fires. All action blocks have access to the root context consisting of the following fields:

- `.Kevt` accesses the underlying event that triggered the rule. Refer to this [link](https://github.com/rabbitstack/fibratus/blob/83cd37820b208846809f82b19e857bff6f4eb415/pkg/kevent/kevent.go#L55) to inspect all possible subfields. 
For sequence group policies, a list of all matched events is given instead. Thus, accessing a matching event for the specific group is accomplished with the `.Kevts.k{rule-number}` expression. For example, to access the process name of the event in the first rule you would use an expression like `.Kevts.k1.PS.Name`.
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
In the case of sequence rule policies, we can access the desired event reference by including the ordinal which points to the index in the rules array. This way, `%1.ps.name` would yield the name of the process in the first rule, while `%2.file.name` gives us the filename located in the event reference of the second rule. Both, title and text permit including Markdown or HTML tags.

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

### Stateful rules

Adversaries often employ advanced techniques which may be daunting to detect without combining events from different data sources. For example, detecting a remote connection attempt followed by the execution of a command shell by the same process that initiated the connection can't be expressed with regular `include` policies. Enter `sequence` policies. Sequence policies piggyback on stateful event tracking. These policies can express complex runtime threat detection scenarios. Let's peer into the structure of the sequence group policy.

```yaml
- group: LSASS memory dumping via legitimate or offensive tools
  description: |
    Adversaries may attempt to access credential material stored in the
    process memory of the Local Security Authority Subsystem Service (LSASS).
    After a user logs on, the system generates and stores a variety of credential
    materials in LSASS process memory. These credential materials can be harvested
    by an administrative user or SYSTEM and used to conduct Lateral Movement.
    This rule detects attempts to dump the LSAAS memory to the disk by employing legitimate
    tools such as procdump, Task Manager, Process Explorer or built-in Windows tools such
    as comsvcs.dll.
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
  policy: sequence
  rules:
    - name: LSASS local process object acquired
      condition: >
        open_process
            and
        ps.access.mask.names in ('ALL_ACCESS', 'CREATE_PROCESS')
            and
        ps.sibling.name ~= 'lsass.exe'
            and
            not
        ps.exe imatches
            (
              '?:\\Windows\\System32\\svchost.exe',
              '?:\\ProgramData\\Microsoft\\Windows Defender\\*\\MsMpEng.exe'
            )
    - name: LSASS dump written to the file system
      condition: >
        ps.exe = $1.ps.exe
            and
        write_minidump_file
      max-span: 2m
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

1. As with regular group policies, the name is also mandatory in the sequence policies.
2. Every sequence group requires at least two rule definitions. The rules can refer to partial events matched by upstream rules. This is achieved with **pattern bindings**. The syntax for a pattern binding is expressed with the `$` symbol followed by the scalar number that refers to the position where the rule is declared in the `rules` array. The remaining segment of the path is a well-known filter field identifier. For example, in the above rule group, we require that the process acquiring the object on the `lsass.exe` is equal to the process writing the minidump file.
3. Sometimes we want to restrict the occurrence of a specific event within a time frame. This is the purpose of the `max-span` attribute. Following the previous example, the group matches if the minidump file is written within the two-minute time window after acquiring the `lsass.exe` process object. Otherwise, all partial matches are discarded and the evaluation phase starts over again.
4. Unlike `include` group policies, `sequence` policy has group-level actions. The action is executed when all rules in the group match. The action context contains a list of events that triggered each individual rule in the group.
