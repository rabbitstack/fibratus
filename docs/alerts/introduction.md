# Watchdogging Kernel Events

Fibratus has the ability to generate alerts when an unexpected flow is detected in the system. Some alerts are generated out of the box, for example, when the [YARA scanner](/yara/scanning) yields rule matches. Other alerts are emitted directly from [filaments](/alerts/filaments) when the conditions are met.

The alert has the following key components:

- **title** summarizes the purpose of the alert.
- **text** is the message that further explains what this alert is about as well as actors involved.
- **tags** contains a sequence of tags for categorizing the alerts.
- **severity** determines the severity of the alert. Possible values are `normal`, `medium`, `critical`.

To send alert notifications, use [alert senders](/alerts/senders).
