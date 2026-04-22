# Callstacks

##### Callstack reconstructs the sequence of function calls that led to the current thread state. Return addresses obtained directly from kernel space, are symbolized and enriched with a vital context that can be leveraged to boost behavioral detections and reduce false positive alerts. 

By resolving raw instruction pointers into human-readable symbols such as module paths, function names, and offsets, Fibratus enables analysts to trace behavior back to its true origin, even across user-mode and kernel-mode boundaries. This capability is particularly valuable for detecting stealthy or indirect activity as it exposes the full execution path rather than relying solely on the initiating process. Callstacks can be filtered, symbolized, and enriched with metadata, allowing them to be incorporated into [detection rules](../rules/fields.md) and forensic workflows for high-fidelity behavioral analysis.

A typical callstack summary is depicted in the screenshot below, delineating kernel, system, and user frames provenance.

!> For the [console](outputs/console.md) output to render callstack frames, the template shall define the `{{ .Callstack }}` segment. Segments can be customized by overriding the default [rendering template](outputs/console?id=templates).

![Callstacks](images/callstacks.png "Callstacks")

Each line corresponds to the frame stack consisting of:

- function call return address, for example, `0x7ffb5c1d0396`
- full path of the module containing the executed function, such as `C:\Windows\System32\kernel32.dll`. If the call is invoked from a floating memory region, then the module name is marked as `unbacked`
- name of the symbol mapping to the return address, for example, `CreateProcessAsUserW`
- offset within the symbol

Stack enrichment is applied to the following event types:

- `CreateProcess`
- `CreateThread`
- `TerminateThread`
- `SetThreadContext`
- `LoadImage`
- `RegCreateKey`
- `RegDeleteKey`
- `RegSetValue`
- `RegDeleteValue`
- `CreateFile`
- `DeleteFile`
- `RenameFile`
- `VirtualAlloc`
- `OpenProcess`
- `OpenThread`
- `CreateSymbolicLinkObject`
- `SubmitThreadpoolWork`
- `SubmitThreadpoolCallback`
- `SetThreadpoolTimer`

Stack enrichment is enabled by default, but can be controlled via `--eventsource.stack-enrichment` configuration flag. To enable stack enrichment for kernel space return addresses, the `symbolize-kernel-addresses` config option needs to be set to `true`
