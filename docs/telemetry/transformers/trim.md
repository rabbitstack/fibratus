# Trim

##### The `trim` transformer removes specified prefixes and/or suffixes from string event parameters. This is useful for normalizing values by stripping redundant or contextual markers, such as path segments, protocol prefixes, or formatting artifacts. The transformation operates only on string parameters and ensures that only the defined leading or trailing substrings are removed, leaving the core value intact.

## Configuration 

The `trim` transformer configuration is located in the `transformers.trim` section.

### `enabled`

Indicates if the `trim` transformer is enabled.

### `prefixes`

Contains the list of parameter names and prefixes that are trimmed from the parameter's value.

### `suffixes`

Contains the list of parameter names and suffixes that are trimmed from the parameter's value.

As an example, the following config trims the `HKEY_LOCAL_MACHINE` prefix and the `Keys` suffix from the `key_path` parameter value.

```yaml
prefixes:
- param: key_path
  trim: HKEY_LOCAL_MACHINE
suffixes:
- param: key_path
  trim: Keys
```
