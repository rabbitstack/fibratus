# Outputs

##### Fibratus provides a wide range of output sinks for transmitting telemetry events. While local [captures](../../captures.md) are often sufficient for inspection and analysis, the event stream can also be forwarded to external systems such as message brokers or search and analytics platforms, for example, RabbitMQ or Elasticsearch, enabling centralized processing, storage, and observability at scale.

Each output exposes a comprehensive set of configuration options, allowing you to fine-tune how events are transmitted and integrated with downstream systems.

### Event serialization

Events are serialized in JSON format by default. Since each event may contain a large number of attributes, you can control which fields are included in the serialized output via the `event` section of the configuration file.

The following options determine which parts of the process state are included:

* `serialize-threads` include thread metadata
* `serialize-modules` include loaded modules (e.g. DLLs)
* `serialize-handles` include allocated process handles
* `serialize-pe` include [Portable Executable](https://en.wikipedia.org/wiki/Portable_Executable) (PE) metadata
* `serialize-envs` include environment variables

Adjusting these settings allows you to balance the level of detail against performance and storage considerations.
