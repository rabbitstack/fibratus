# Parsing, Enriching, Transforming

Transformers are responsible for mutating, parsing, or enriching kernel events before they hit the output sink. They offer a fair amount of flexibility to shape the structure of the event parameters. Transformers are applied sequentially to every event routed to the output sink.

You can parameterize transformers via the `yml` configuration in the `transformers` section.
