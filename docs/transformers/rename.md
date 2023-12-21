# Rename

The `rename` transform rename one or more parameters. Given the following event parameters:

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

And the `rename` transformer configuration:

```
transformers:
  rename:
    enabled: true
    kparams:
      - old: file_name
        new: file
      - old: file_object
        new: fobj
```

The event will contain the following parameters:

```
{
  'name': 'C:\WINDOWS\system32\config\systemprofile\AppData\WindowsApps\',
  'fobj': 'ffffa88c7ea077d0',
  'irp': 'ffffa88c746b2a88',
  'operation': 'supersede',
  'share_mask': 'rw-',
  'type': 'directory'
}
```

### Configuration {docsify-ignore}

The `rename` transformer configuration is located in the `transformers.rename` section.

#### enabled

Indicates if the `rename` transformer is enabled.

**default**: `false`

#### kparams

Contains the list of old/new parameter name mappings. `old` key represents the original parameter name, while `new` is the new parameter name.
