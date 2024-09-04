# Transporting Events

Fibratus delivers a diverse array of output sinks to route the events. When captures are not enough, you may opt for forwarding the event stream to remote destinations such as RabbitMQ brokers or Elasticsearch clusters. Outputs expose a rich set of configuration knobs that enable to fine-tune the behaviour of the event flow transmission.

### Event serialization tweaking {docsify-ignore}

JSON is the default serialization format for events. Since the event state contains a vast of attributes, you can specify which fields are serialized through configuration properties located in the `kevent` section.

- `serialize-threads` indicates whether the threads metadata are serialized as part of the process, and consequently, the event state
- `serialize-images` decides whether modules such as Dynamic Linked Libraries are serialized as part of the process state
- `serialize-handles` determines whether allocated process handles are serialized as part of the process state
- `serialize-pe` indicates if PE (Portable Executable) metadata are serialized as part of the process state
- `serialize-envs` indicates if environment variables are serialized as part of the process state
