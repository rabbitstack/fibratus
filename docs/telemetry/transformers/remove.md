# Remove

##### The `remove` transform is used to exclude specific parameters from an event before it is forwarded or persisted. This is useful for reducing payload size, removing sensitive fields, or tailoring events to the needs of downstream consumers.

## Configuration 

The `remove` transformer configuration is located in the `transformers.remove` section.

### `enabled`

Indicates if the `remove` transformer is enabled.

### `params`

Represents the list of parameters that are removed from the event.
