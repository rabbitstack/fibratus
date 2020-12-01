# Trim

The `trim` transformer cuts off specified prefixes/suffixes from the string event parameters. Given the following event parameters:

```
{
  'key_handle': 0,
  'key_name': 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\StateSeparation\Keys',
  'status': 'key not found'
}
```

And the `trim` transformer configuration:

```
replace:
  enabled: true
  prefixes:
    - kparam: key_name
      trim: HKEY_LOCAL_MACHINE
  suffixes:
    - kparam: key_name
      trim: Keys
```

The transformer produces the following parameters:

```
{
  'key_handle': 0,
  'key_name': '\System\CurrentControlSet\Control\StateSeparation\',
  'status': 'key not found'
}
```

### Configuration {docsify-ignore}

The `trim` transformer configuration is located in the `transformers.trim` section.

#### enabled

Indicates if the `trim` transformer is enabled.

**default**: `false`

#### prefixes

Contains the list of parameter names and prefixes that are trimmed from the parameter's value.

#### suffixes

Contains the list of parameter names and suffixes that are trimmed from the parameter's value.
