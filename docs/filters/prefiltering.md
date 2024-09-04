# Prefiltering

Sometimes it is useful to drop certain events either by image (process) name or event type once the event is peeked from the tracing buffer. Besides this, the kernel stream consumer can be configured to ignore events at the `ETW` session level. This can drastically reduce the impact on the system load if you're not interested in events that may produce an immense volume of data. 

The above is the summary of configuration options that influence the collection of events. These options are placed in the `kstream` section of the configuration file.

- `enable-thread` enables/disables the collection of the thread-related kernel events
- `enable-registry` enables/disables the collection of registry kernel events
- `enable-net` enables/disables the collection of network kernel events
- `enable-fileio` enables/disables the collection of the file system events
- `enable-image` enables/disables the collection of image loading/unloading events
- `enable-handle` enables/disables the collection of handle events
- `enable-audit-api` enables/disables kernel audit API calls events
- `enable-mem` enables/disables the collection of memory events
- `enable-dns` enables/disables DNS telemetry

### Excluding processes or events {docsify-ignore}

If you want to permanently exclude specific events or processes that produce them from the event flow, you can achieve this by defining the blacklist in the `kstream.blacklist` configuration section:

- `events` contains a list of event names that are dropped from the event stream.
- `images` contains a list of case-sensitive process image names including the extension. Any event originated by the image specified in this list is dropped from the event stream.
