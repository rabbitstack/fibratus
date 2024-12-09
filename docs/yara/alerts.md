# Alerts

Alerts on rule matches are automatically sent via all active alert senders.

##  Event metadata {docsify-ignore}

When the event triggers a specific YARA rule, its metadata is automatically decorated with the rule matches. 
The `yara.matches` tag contains the JSON array payload where each object represents the YARA rule match. For example:

```json
[
  {
    "rule": "AnglerEKredirector ",
    "namespace": "EK",
    "tags": null,
    "metas": [
      {
        "identifier": "description",
        "value": "Angler Exploit Kit Redirector"
      }
    ],
    "strings": "..."
  },
  {
    "rule": "angler_flash_uncompressed ",
    "namespace": "EK",
    "tags": [
      "exploitkit"
    ],
    "metas": [
      {
        "identifier": "description",
        "value": "Angler Exploit Kit Detection"
      }
    ],
    "strings": "..."
  }
]
```
