# Remove

The `remove` transform drops parameters from the event. Given the following event parameters:

```
{
  'file_name': 'C:\WINDOWS\system32\config\systemprofile\AppData\WindowsApps\',
  'file_object': 'ffffa88c7ea077d0',
  'irp': 'ffffa88c746b2a88',
  'operation': 'supersede',
  'share_mask': 'rw-',
  'type': 'directory'
}
```

And the `remove` transformer configuration:

```
transformers:
  remove:
    enabled: true
    kparams:
      - irp
      - share_mask
      - file_object
```

The event will contain the following parameters:

```
{
  'file_name': 'C:\WINDOWS\system32\config\systemprofile\AppData\WindowsApps\',
  'operation': 'supersede',
  'type': 'directory'
}
```

### Configuration {docsify-ignore}

The `remove` transformer configuration is located in the `transformers.remove` section.

#### enabled

Indicates if the `remove` transformer is enabled.

**default**: `false`

#### kparams

Represents the list of parameters that are removed from the event.
