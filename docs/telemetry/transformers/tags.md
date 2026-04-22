# Tags

##### The `tags` transformer appends custom tags to an event’s metadata field. This allows events to be enriched with additional contextual labels that can later be used for filtering, classification, or routing. Tags are typically used to mark events with domain-specific or operational metadata—such as environment, source category, or processing stage without modifying the original event payload.


## Configuration 

The `tags` transformer configuration is located in the `transformers.tags` section.

### `enabled`

Indicates if the `tags` transformer is enabled.

### `tags`

Defines the list of tags to be appended to the event metadata. Each value is added as a static label, enriching the event with additional contextual information.

Tag values can also be dynamically resolved from environment variables by enclosing the variable name in `%`, for example, `%ENV_VAR%`. This allows tags to reflect runtime configuration without requiring changes to the static configuration file.
