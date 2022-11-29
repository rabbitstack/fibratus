# Driver events

#### LoadDriver

Driver loading events are triggered when the driver object is loaded into the kernel. The `image_name` parameter represents the full path of the driver file located in the file system.
Driver events are consumed from the `Microsoft Antimalware Engine` ETW provider, thus the events are only published if the Windows Defender Antivirus realtime protection is activated.

An alternative route for detecting driver loading events is based on observing the [handle manager](kevents/handle.md) events. For example, a filter expression for pinpointing such events could be arranged as follows.

```
kevt.name = 'CreateHandle'
    and
handle.type = 'Driver'
```

Rule writers are encouraged to use the `load_driver` macro from the [macro library](https://github.com/rabbitstack/fibratus/blob/master/rules/macros/macros.yml). This macro seamlessly handles the detection of driver loading depending on whether direct events are available or either handle manager tracking is required.