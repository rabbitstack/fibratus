# Firing Alerts

Fibratus has the ability to generate security alerts when the detection or [YARA](/yara/scanning) rule matches. Additionally, alerts can be emitted directly from [filaments](/alerts/filaments).

The alert has the following key components:

- **title** summarizes the purpose of the alert.
- **text** is the message that further explains what this alert is about as well as actors involved.
- **tags** contains a sequence of tags for categorizing the alerts.
- **severity** determines the severity of the alert. Possible values are `normal`, `medium`, `critical`.

To send alert notifications, use [alert senders](/alerts/senders).
