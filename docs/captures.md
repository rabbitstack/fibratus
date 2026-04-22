# Captures

##### Captures allow you to **record and replay the full stream of events** together with enough system state to reconstruct what happened at a given point in time. A capture acts as a *time capsule* of system activity enabling deterministic, offline analysis of behaviors that originally occurred on another machine.

This makes captures especially valuable for post-mortem incident investigations, malware analysis and reverse engineering, detection rule development and testing, and evidence material.

A capture is a file with the `.cap` extension that contains the snapshot of system state and chronologically ordered stream of events. Together, these allow rebuilding process context during replay, as if events were happening live. Think of captures as a recording of the event pipeline that can be replayed with full analytical capabilities.

## Capturing events

Capturing is initiated via the `fibratus capture` command.

<Terminal>
$ fibratus capture -o events

</Terminal>

This command starts recording the telemetry, writes all events to `events.cap` in the current directory. The `-o` (output) flag specifies the capture file name. To stop capturing, press `Ctrl + C` After stopping, a summary is printed including number of captured events, number of processes, and the capture size.

?> The `capture` command automatically overwrites any existing capture file with the same name located in the current directory.

You can restrict which events are recorded by providing a [filter](telemetry/filtering.md) expression. This is useful for reducing the capture size, focusing on specific subsystems (file, registry, network, etc.), and minimizing noise during analisys. Filtering at capture time is more efficient than filtering during replay when dealing with high event volumes

<Terminal>
$ fibratus capture evt.category = 'file' -o fs-events
</Terminal>

## Replaying captures

Replaying a capture restores system state and reprocesses events as if they were happening in real time. Replaying is initiated via the `fibratus replay` command.

<Terminal>
$ fibratus replay -k events

</Terminal>

During replay process and handle state are rebuilt. Events are emitted through the same pipeline as live data, so [filters](telemetry/filtering.md) or [filaments](filaments.md) can be applied.

You can apply filters when replaying to focus on relevant events and drill down into specific behaviors iterating quickly during investigations.

<Terminal>
$ fibratus replay file.path contains 'Temp' -k fs-events

</Terminal>

Captures can be used as input for [filaments](filaments.md) enabling offline analytics and automation. This is particularly useful for testing filaments against real-world data. The `-f` flag specifies the filament against which the capture events are processed.

<Terminal>
$ fibratus replay -f watch_files -k fs-events

</Terminal>

## Capture format and internals

Under the hood, captures are stored as [zstd](https://es.wikipedia.org/wiki/Zstandard) compressed streams. ZSTD provides a strong balance between the compression ratio and runtime overhead.

A `.cap` file consists of:

1. **Header**
   * Magic
   * Major/minor version
   * Flags
2. **Handle snapshot**
   * All active kernel handles at capture start
3. **Event stream**
   * Ordered events

The process state is not explicitly stored. Instead, it is reconstructed during replay by processing events such as process enumeration and lifecycle notifications.
Fibratus increments the major version of the `cap` format when breaking changes are introduced. Captures with mismatched major versions may not replay. This way, the compatibility is guaranteed between capture producer version and replay version.
