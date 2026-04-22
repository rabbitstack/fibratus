# Alert

##### Fibratus can generate security alerts via multiple delivery channels when a detection rule or a [YARA](../../yara.md) rule matches. Alerts can also be emitted programmatically from [filaments](../../filaments.md), enabling fully customizable alerting workflows.

Each alert consists of the following key components:

| COMPONENT  | DESCRIPTION |
| :---       | :----  |
| `id` | A unique identifier for the alert, represented as a UUID. For detection alerts, this identifier is immutable, meaning it remains constant for a given rule instance. |
| `title` |   A short, human-readable summary describing the alert. |
| `text` | A detailed message providing additional context, such as the activity observed and the entities involved. |
| `description`| Provides additional context about the alert, typically derived from the rule description. |
| `tags` | A list of tags used to categorize and filter alerts. |
| `lables` | A list of labels in key/value format. |
| `severity` | Indicates the importance of the alert. Supported values are `low`, `medium`, `high` and `critical` |
| `events` | List of events that participated in the alert containing full process context and callstacks. |

Alerts are automatically generated when a rule matches and are dispatched through all configured alert senders. By default, the `Eventlog` sender is enabled, publishing security alerts to the Windows Event Log.

## Customizing alerts

By default, the rule name is used as the alert title. To provide richer context, rules can define an `output` attribute, which is used as the alert message. The `output` field supports [Markdown](https://www.markdownguide.org/) formatting, enabling enhanced presentation and better readability in alerts.

The `output` field supports field interpolation, allowing dynamic insertion of event data into the alert. Fields are referenced using format modifiers prefixed with `%`. In this example, `%ps.exe` is resolved to the full path of the process executable associated with the event.

```yaml
output: >
  %ps.exe process spawned a command shell after connecting to the remote endpoint
```

Format modifiers correspond to well-known event fields and provide a concise way to reference structured data within alerts. They enable rules to produce highly contextual and actionable messages without hardcoding values.
For sequence rules, alert messages can reference specific events within the sequence by using ordinal prefixes. The ordinal represents the position of the event in the sequence. For example, `%1.ps.name` derives the process name from the first event in the sequence, while `%2.file.name` extracts the file name from the second event in the sequence.

This allows precise attribution of actions across multiple related events. As an example:

```yaml
output: >
  Detected an attempt by <code>%1.ps.name</code> process to access
  and read the memory of the **Local Security Authority Subsystem Service**,
  followed by writing the <code>%2.file.name</code> dump file to disk.
```

## Publishing alerts

Alert notifications can be delivered via email, Slack, Eventlog and other alert senders. Alerts may be sent through multiple senders simultaneously. Alert sender configuration is defined in the `alertsenders` section of the YAML configuration file.

### `Eventlog`

The `eventlog` alert sender sends alerts to the [Windows Eventlog](https://sematext.com/glossary/what-is-windows-event-log/). Eventlog alert sender configuration is located in the `alertsenders.eventlog` section. Here are the available configuration knobs.

##### `enabled`

Indicates whether the `eventlog` alert sender is enabled.

##### `verbose`

Enables/disables the verbose mode. In verbose mode, the full event context, including all parameters and the process information are included
in the log message.

##### `format`

Can be `pretty` or `json`

### `Mail`

The mail alert sender emits alert notifications through the `SMTP` protocol.

!> If you are using a Gmail SMTP provider, you might need to configure [App Passwords](https://support.google.com/accounts/answer/185833?hl=en) for your account.

The `mail` alert sender configuration is located in the `alertsenders.mail` section. Here are the available configuration knobs.

#### `enabled`

Indicates if the alert sender is enabled.

#### `host`

Represents the host name of the SMTP server where the alert notification is sent.

#### `port`

Represents the port number of the SMTP server.

#### `user`

Specifies the user name when authenticating to the SMTP server.

#### `password`

Specifies the password when authenticating to the SMTP server.

#### `from`

Determines the sender's email address.

#### `to`

Specifies the list of the recipient email addresses.

#### `use-template`

Indicates if the alert is rendered using the built-in HTML template.

### `Slack`

The `slack` alert sender forwards alerts to Slack workspaces. You'll have to [activate](https://slack.com/intl/en-es/help/articles/115005265063-Incoming-webhooks-for-Slack) incoming webhooks and associate the webhook to your Slack workspace to be able to emit the alerts. The `slack` alert sender configuration is located in the `alertsenders.slack` section.

#### `enabled`

Indicates whether the `slack` alert sender is enabled.

#### `url`

Represents the Webhook URL of the workspace where alerts will be dispatched. The Webhook URL has the following format: `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`

#### `workspace`

The name of the Slack workspace where alerts are routed.

#### `channel`

Is the slack channel in which to post alerts.

#### `emoji`

Represents the emoji icon surrounded in `:` characters for the Slack bot.

### `Systray`

The `systray` alert sender sends alerts to the systray notification area. Alert sender configuration is located in the `alertsenders.systray` section.

#### `enabled`

Indicates whether the `systray` alert sender is enabled.

#### `sound`

Indicates if the associated sound is played when the balloon notification is shown.

#### `quiet-mode`

Instructs not to display the balloon notification if the current user is in quiet time. During this time, most notifications should not be sent or shown. This lets a user become accustomed to a new computer system without those distractions. Quiet time also occurs for each user after an operating system upgrade or clean installation.

### `Filaments`

Filaments can generate alerts by invoking the `emit_alert` function. Once emitted, the alert is automatically propagated to all active alert senders. The `emit_alert` function accepts two required positional arguments and two optional keyword arguments:

```python
emit_alert(title, text, severity='normal', tags=[])
```

| ARGUMENT  | DESCRIPTION | REQUIRED? |
| :---       | :----  | :---- |
| `title` | A short summary of the alert. | yes |
| `text` | A detailed message describing the alert. | yes |
| `severity` | Alert severity level. Defaults to `normal` | no |
| `tags` | A list of tags used to categorize the alert. | no |

The following example demonstrates how to emit an alert from a filament that detects registry persistence activity. In this example, the alert title dynamically includes the registry key path, while the `text` function provides additional context derived from the event.

```python
emit_alert(
    f'Registry persistence detected in path {event.params.registry_path}',
    text(event),
    severity='medium',
    tags=['registry persistence']
)
```