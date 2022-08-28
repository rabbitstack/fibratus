# Prefiltering

Sometimes it is useful to drop certain events either by image (process) name or event type once the event is peeked from the tracing buffer. Besides this, the kernel stream consumer can be configured to ignore events at the `ETW` session level. This can drastically reduce the load if you're not interested in particular events that are producing an immense volume of data.

The above is the summary of configuration options that influence the collection of kernel events by the `Kernel Logger`. These options are placed in the `kstream` section of the configuration file.

- `enable-thread` enables/disables the collection of the thread-related kernel events
- `enable-registry` enables/disables the collection of registry kernel events
- `enable-net` enables/disables the collection of network kernel events
- `enable-fileio` enables/disables the collection of the file system events
- `enable-image` enables/disables the collection of image loading/unloading events
- `enable-handle` enables/disables the collection of handle events

### Blacklisting {docsify-ignore}

If you want to permanently exclude specific kernel events or processes that produce them from the event flow, you can achieve this by defining the blacklist in the `kstream.blacklist` configuration section:

- `events` contains a list of kernel event names that are dropped from the event stream.
- `images` contains a list of case-sensitive process image names including the extension. Any event originated by the image specified in this list is dropped from the event stream.
