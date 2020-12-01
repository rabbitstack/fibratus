# Tags

The `tags` transformer appends custom tags to event's metadata field.

### Configuration {docsify-ignore}

The `tags` transformer configuration is located in the `transformers.tags` section.

#### enabled

Indicates if the `tags` transformer is enabled.

**default**: `false`

#### tags

Contains the list of tags that are appended to event metadata. Values can be fetched from environment variables by enclosing them in `%`. Example:

```
tags:
  enabled: true
  tags:
    - key: env
      value: prod
    - key: drive
      value: %HOMEDRIVE%
```
