# Rename

##### The `rename` transform is used to rename one or more event parameters before the event is emitted or forwarded. This is useful for standardizing field names, resolving naming conflicts, or adapting the event schema to match downstream expectations.

## Configuration 

The `rename` transformer configuration is located in the `transformers.rename` section.

### `enabled`

Indicates if the `rename` transformer is enabled.

### `params`

Defines a list of mappings between original and new parameter names. The `old` key specifies the existing parameter name in the event, while the `new` key defines the name it should be renamed to during transformation. As an example, the following configuration renames the `username` parameter to `user` and `dport` parameter to `dst_port`

```yaml
params:
  - old: username
    new: user
  - old: dport
    new: dst_post
```
