# Replace

The `replace` transformer replaces all non-overlapping instances of string parameters with the specified substring. Given the following event parameters:

```
{
  'key_handle': 0,
  'key_name': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\StateSeparation\Keys',
  'status': 'key not found'
}
```

And the `replace` transformer configuration:

```
replace:
  enabled: true
  replacements:
    - kparam: key_name
      old: HKEY_LOCAL_MACHINE
      new: HKLM
```

The transformer produces the following parameters:

```
{
  'key_handle': 0,
  'key_name': 'HKLM\System\CurrentControlSet\Control\StateSeparation\Keys',
  'status': 'key not found'
}
```

### Configuration {docsify-ignore}

The `replace` transformer configuration is located in the `transformers.replace` section.

#### enabled

Indicates if the `replace` transformer is enabled.

**default**: `false`

#### replacements

Contains the list of parameter replacements. For each target event parameter identified by the `kparam` key, `old` represent the substring  that will be replaced by the `new` substring.
