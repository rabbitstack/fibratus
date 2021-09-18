# Rules

CLI filters offer a decent amount of flexibility when digging into the event flux, but they fall short to express complex filtering decisions. This is where rules come to the rescue. Rules are a collection of grouped filters defined in `yaml` files. Each group contains a set of attributes that dictate whether the event passes through the stream or gets dropped. Specifically, the following attributes describe a group:

- **name** associates a meaningful name to the group such as `Suspicious process terminations`
- **selector** indicates the event type or event category that a certain filter group can capture. For example,`CreateProcess` or `registry`
- **enabled** specifies whether the group is active
- **policy** determines the action that's taken on behalf of the incoming event. There are two types of policies: `include` and `exclude`. Include policy filters the event if one of the filters in the group matches, even though this behavior can be tweaked by setting the `relation` attribute. On the other hand, the exclude policy drops the event when a match occurs in the group.
- **relation** controls the group matching criteria. Possible values for the group relation are `and` and `or`. When the `and` relation type is specified, all filters in the group have to match for the event to get accepted. Conversely, the `or` relation type requires only one filter in the group to evaluate to true for accepting the event.
- **filters** contain an array of filtering expressions. Each expression is composed of a descriptive filter name, definition, and an optional action that is executed when the rule is triggered.

### Loading rules {docsify-ignore}

By default, rules reside inside `%PROGRAM FILES%\Fibratus\Config\Rules` directory. You can load any number of rule files from file system paths or URL locations.

Edit the main [configuration](/setup/configuration?id=files) file. Go to the `filters` section where the following `yaml` fragment is located:

```yaml
filters:
  rules:
    from-paths:
      - C:\Program Files\Fibratus\Config\Rules\Default\default.yml
    from-urls:
      - https://raw.githubusercontent.com/rabbitstack/fibratus/master/configs/rules/default/default.yml
```

- `from-paths` represents an array of file system paths pointing to the rule definition files
- `from-urls` is an array of URL resources that serve the rule definitions

### Defining rules {docsify-ignore}

As we mentioned previously, rules are bound to groups. Each group targets a specific event type or event category. Let's have a glimpse at an example of a group with two rules.

```yaml
- group: Suspicious file creation operations                               
  selector:
    type: CreateFile
  enabled: true
  policy: include
  relation: or
  from-strings:
    - name: Startup links and shortcut modifications
      def: file.operation = 'create'
              and
           file.name icontains
           (
              '\\Start Menu',
              '\\Startup\\'
           )
    - name: Microsoft Outlook attachments
      def: file.operation = 'create' and file.name icontains '\\Content.Outlook\\'
   tags:
    - persistence
    - lateral movement
```

1. The group needs a mandatory name. You can define as many groups as you like, even if they target the same event type or category. Later on, during the loading stage, they are merged into a single group.

2. Every group has a selector. The selector dictates which events are captured by the group. In our example, only `CreateFile` events would get routed to this group. An alternative option for `type` is the `category` attribute that can have one of the values described in the [category](kevents/anatomy?id=canonical-fields) canonical field. Setting the `category: file` attribute would result in all file events being captured by the group.

3. Sometimes it comes in handy to temporarily disable a specific group. This is the purpose of the `enabled` attribute. It can be omitted and by default, it is equal to `true`.

4. Group policy specifies whether the event that matched a rule is propagated to upstream [output](/outputs/introduction) or  is rejected. This behaviour is accomplished with `include` and `exclude` policies respectively. Exclude policies take precedence over include policies. Simply put, if we had another group with the `exclude` policy targeting the `CreateFile` event type or the `file` category, any match occurring in the exclude group would drop the event. If not specified, the group policy is equal to `include`.

5. If we need all the rules in a group to produce a match in order to accept the event, we can tune up the `relation` attribute. By default, the `or` relation allows for the group match to get promoted if a single rule in a group is evaluated to be true. On the contrary, the `and` relation type would instruct the rule engine to pass the event only if all rules are matched.

6. The collection of rules is specified in the `from-strings` attribute. You may notice the `def` element contains the well-known filter expression we used to employ in the CLI filters.

7. You can attach an arbitrary number of `tags` to each group.

#### Externalizing values

To avoid bloating rule files with long file paths, command-line signatures, registry keys, or other resources, it is possible to store them separately in so-called `values` files. [Here](https://github.com/rabbitstack/fibratus/blob/master/configs/rules/default/values.yml) is an example of such a file. Just make sure to place the `values.yml` file within the same directory where rule files are located.

To fetch any value from the `values.yml` file, use the Go [template](https://pkg.go.dev/text/template) syntax with the `.Values` field accessor. Assuming you have defined the following `values.yml` file. 

```yaml
processes:
  comm:
    svchost:
      - C:\\Windows\\system32\\svchost.exe -k appmodel -s StateRepository
      - C:\\Windows\\system32\\svchost.exe -k dcomlaunch -s LSM
      - C:\\Windows\\system32\\svchost.exe -k defragsvc
```

To to get a comma-separated list of string values enclosed inside parentheses, you would use the following snippet in the rule definition:

```yaml
- name: svchost
  def: ps.comm iin {{ .Values.processes.comm.svchost | stringify }}
```

Note we start the field path with the `.Values` prefix and next specify the rest of the segments as declared in the `yml` file. The result is fed to the `stringify` function that simply quotes  each element in the array and encloses it inside parentheses.

This filter would get expanded to the following block.

```yaml
- name: svchost
  def: ps.comm iin 
    (
        'C:\\Windows\\system32\\svchost.exe -k appmodel -s StateRepository', 
        'C:\\Windows\\system32\\svchost.exe -k dcomlaunch -s LSM', 
        'C:\\Windows\\system32\\svchost.exe -k defragsvc'
    )
```


#### Templating {docsify-ignore}

One of the compelling features of rule files is the ability to use the Go [templating](https://pkg.go.dev/text/template) engine for assisting in filter expression building. This encompass loops, pipelines, functions, and many other facilities. Additionaly, Fibratus includes a set of [predefined](http://masterminds.github.io/sprig/) functions ranging from string to cryptographic and math functions.

#### Actions {docsify-ignore}

Apart from letting the event continue its journey when the rule matches, it is also possible to attach an `action` to execute when the rule is triggered. Currently, the following actuators are available in rule actions:

- `emit` sends an alert via alert [senders](/alerts/senders). The `emit` actuator requires a title and text, and optionally, you can specify the severity level and a list of tags.
- `kill` terminates a process with the specified pid.

Let's see the following example:

```yaml
- group: Suspicious remote thread creations
  selector:
    type: CreateThread
  from-strings:
    - name: Fishy remote threads
      def: kevt.pid != thread.pid
      action: |
        {{ $title := cat "Identified remote thread creation in"
          .Kevt.Kparams.exe }}
        {{  $text := cat "Injected by" .Kevt.PS.Exe }}
        {{ emit $title $text }}
```

Each time we detect a thread creation event happening in a remote process the `action` block is executed. When in the action scope, the template has access to various fields:

- `.Kevt` accesses the underlying kernel event. Refer to this [link](https://github.com/rabbitstack/fibratus/blob/83cd37820b208846809f82b19e857bff6f4eb415/pkg/kevent/kevent.go#L55) to inspect all possible subfields.
- `.Filter` provides access to filter attributes. The following subfields are available:
    - `.Filter.Name` gets the filter/rule name
    - `.Filter.Def` gets the filter expression
- `.Group` provides access to group attributes. The following subfields are available:
    - `.Group.Name` gets the group name
    - `.Group.Selector` returns the selector
    - `.Group.Policy` returns the group policy
    - `.Group.Relation` returns the group relation
    - `.Group.Tags` fetches group tags

We have used the `cat` function to concatenate string literals with fields. Finally, we call into the `emit` actuator passing the title and text arguments.

#### Event rule metadata {docsify-ignore}

For include groups matches, the rule and group name are pushed into the event metadata stitching the rule with the event that triggered it. `rule.name` and `rule.group` tags identify the rule and the group name respectively. For example, you can configure the console output [template](outputs/console?id=templates) to print the metadata of the event. Similarly, other outputs will produce the corresponding JSON dictionary with the rule tags.

