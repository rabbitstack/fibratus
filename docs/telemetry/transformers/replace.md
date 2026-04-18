# Replace

##### The `replace` transformer substitutes all non-overlapping occurrences of a specified substring within string parameters. This is useful for normalizing values, redacting sensitive information, or standardizing event data before it is forwarded or stored. The transformation operates on a simple find-and-replace basis, scanning the target parameter and replacing every match with the configured replacement string.


## Configuration 

The `replace` transformer configuration is located in the `transformers.replace` section.

### `enabled`

Indicates if the `replace` transformer is enabled.

### `replacements`

Defines a list of parameter replacement rules. Each rule targets a specific event parameter identified by the `param` key. Within that parameter, every occurrence of the substring specified in `old` is replaced with the value defined in `new`. As an example, the following config replaces the `HKEY_LOCAL_MACHINE` substring in the `key_path` parameter value with `HKLM`.

```yaml
replacements:
  - param: key_path
    old: HKEY_LOCAL_MACHINE
    new: HKLM
```
