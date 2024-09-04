# Driver events

#### LoadDriver

Driver loading events are triggered when the driver object is loaded into the kernel. Regular `LoadImage` events are triggered when the kernel driver is loaded or when the driver is unloaded, the `UnloadImage` event is received.

An alternative route for detecting driver loading events is based on observing the [handle manager](kevents/handle.md) events. For example, a filter expression for pinpointing such events could be arranged as follows.

```
kevt.name = 'CreateHandle'
    and
handle.type = 'Driver'
```

Rule writers are encouraged to use the `load_driver` macro from the [macro library](https://github.com/rabbitstack/fibratus/blob/master/rules/macros/macros.yml). This macro seamlessly handles the detection of driver loading depending on whether direct events are available or handle manager tracking is required.
