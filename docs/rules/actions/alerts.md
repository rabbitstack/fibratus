# Firing Alerts

Fibratus has the ability to generate security alerts when the detection or [YARA](/yara/scanning) rule matches. Additionally, alerts can be emitted directly from [filaments](/alerts/filaments).

The alert has the following key components:

- **id** the alert identifier represented as UUID.
- **title** summarizes the purpose of the alert.
- **text** is the message that further explains what this alert is about as well as actors involved.
- **tags** contains a sequence of tags for categorizing the alerts.
- **severity** determines the severity of the alert. Possible values are `normal`, `medium`, `critical`.

To send alert notifications, use [alert senders](/alerts/senders).

# Alert Senders

You can send alert notifications to your team through email, Slack, or incident response platforms. The notification can be sent to multiple alert senders. Alert senders configuration resides in the `alertsenders` section of the `yml` file.

- [Mail](/alerts/senders/mail)
- [Slack](/alerts/senders/mail)
- [Systray](/alerts/senders/systray)
- [Eventlog](/alerts/senders/eventlog)

# Eventlog

The `eventlog` alert sender sends alerts to the [Windows Eventlog](https://sematext.com/glossary/what-is-windows-event-log/).

<p align="center">
  <img src="alerts/senders/images/eventlog.gif" style="border-radius: 4px; backdrop-filter: blur(15px) saturate(3); filter: drop-shadow(0 0 0.75rem rgba(30, 30, 30, 0.4));" />
</p>

### Configuration 

The `eventlog` alert sender configuration is located in the `alertsenders.eventlog` section.

#### enabled

Indicates whether the `eventlog` alert sender is enabled.

**default**: `true`

#### verbose

Enables/disables the verbose mode. In verbose mode, the full event context, including all parameters and the process information are included
in the log message.

**default**: `true`

# Mail

The mail alert sender emits alert notifications through the `SMTP` protocol.
!> If you are using a Gmail SMTP provider, you might need to configure [App Passwords](https://support.google.com/accounts/answer/185833?hl=en) for your account

!> If you are using a Gmail SMTP provider, you might need to configure [App Passwords](https://support.google.com/accounts/answer/185833?hl=en) for your account

### Configuration 

The `mail` alert sender configuration is located in the `alertsenders.mail` section.

#### enabled

Indicates if the alert sender is enabled.

**default**: `false`

#### host

Represents the host name of the SMTP server where the alert notification is sent.

#### port

Represents the port number of the SMTP server.

**default**: `25`

#### user

Specifies the user name when authenticating to the SMTP server.

#### password

Specifies the password when authenticating to the SMTP server.

#### from

Determines the sender's email address.

#### to

Specifies the list of the recipient email addresses.

# Slack

The `slack` alert sender forwards alerts to Slack workspaces. You'll have to [activate](https://slack.com/intl/en-es/help/articles/115005265063-Incoming-webhooks-for-Slack) incoming webhooks and associate the webhook to your Slack workspace to be able to emit the alerts.

### Configuration 

The `slack` alert sender configuration is located in the `alertsenders.slack` section.

#### enabled

Indicates whether the `slack` alert sender is enabled.

**default**: `false`

#### url

Represents the Webhook URL of the workspace where alerts will be dispatched. The Webhook URL has the following format: `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`.

#### workspace

The name of the Slack workspace where alerts are routed.

#### channel

Is the slack channel in which to post alerts.

#### emoji

Represents the emoji icon surrounded in `:` characters for the Slack bot.

# Systray

The `systray` alert sender sends alerts to the systray notification area. 

### Configuration 

The `systray` alert sender configuration is located in the `alertsenders.systray` section.

#### enabled

Indicates whether the `systray` alert sender is enabled.

**default**: `false`

#### sound

Indicates if the associated sound is played when the balloon notification is shown.

**default**: `true`

#### quiet-mode

Instructs not to display the balloon notification if the current user is in quiet time. During this time, most notifications should not be sent or shown. This lets a user become accustomed to a new computer system without those distractions. Quiet time also occurs for each user after an operating system upgrade or clean installation.

**default**: `false`

# Filament Alerting

Filaments produce alerts by invoking the `emit_alert` function. The alert is propagated to all active alert senders.

The `emit_alert` function accepts two positional and two keyword arguments. Here is the signature of the function:

```python
emit_alert(title, text, severity='normal', tags=[])
```

An example of calling the `emit_alert` function to generate an alert from the filament that detects registry persistence attacks:

```python
emit_alert(
        f'Registry persistence gained via {kevent.kparams.key_name}',
        text(kevent),
        severity='medium',
        tags=['registry persistence']
)
```