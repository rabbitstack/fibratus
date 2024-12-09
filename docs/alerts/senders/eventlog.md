# Eventlog

The `eventlog` alert sender sends alerts to the [Windows Eventlog](https://sematext.com/glossary/what-is-windows-event-log/).

<p align="center">
  <img src="alerts/senders/images/eventlog.gif" style="border-radius: 4px; backdrop-filter: blur(15px) saturate(3); filter: drop-shadow(0 0 0.75rem rgba(30, 30, 30, 0.4));" />
</p>

### Configuration {docsify-ignore}

The `eventlog` alert sender configuration is located in the `alertsenders.eventlog` section.

#### enabled

Indicates whether the `eventlog` alert sender is enabled.

**default**: `true`

#### verbose

Enables/disables the verbose mode. In verbose mode, the full event context, including all parameters and the process information are included
in the log message.

**default**: `true`
