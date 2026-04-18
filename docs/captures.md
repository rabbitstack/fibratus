# Captures

##### Captures allow you to **record and replay the full stream of events** together with enough system state to reconstruct what happened at a given point in time. A capture acts as a *time capsule* of system activity enabling deterministic, offline analysis of behaviors that originally occurred on another machine.

This makes captures especially valuable for post-mortem incident investigations, malware analysis and reverse engineering, detection rule development and testing, and evidence material.

## What is a capture?

A capture is a file with the `.cap` extension that contains the **snapshot of system state** and chronologically ordered stream of events. Together, these allow Fibratus to rebuild process context during replay, as if events were happening live.

> 💡 Think of captures as a “recording” of the event pipeline that can be replayed with full analytical capabilities.


## Why use captures?

Captures let you “freeze” the system’s event flow and analyze it later, without needing access to the original machine.

### Common use cases

* 🧪 **Malware analysis**
  Record activity on a sandbox or honeypot and replay it safely on your workstation

* 🔍 **Incident response**
  Investigate what happened after an alert was triggered

* 🧰 **Rule development**
  Test detection logic against real-world event sequences

* 🐞 **Troubleshooting**
  Diagnose intermittent or complex issues (e.g., file I/O, networking)

---

## Capturing events

Capturing is initiated via the `fibratus capture` command:

```bash
$ fibratus capture -o events
```

This command:

* Starts recording kernel events
* Writes them to `events.kcap` in the current directory
* Overwrites any existing file with the same name

To stop capturing, press:

```text id="stopcap"
Ctrl + C
```

After stopping, Fibratus prints a summary including:

* Number of captured events
* Number of processes and handles
* Final file size

---

### Output file

* The `-o` (output) flag specifies the capture file name
* The `.kcap` extension is added automatically

```bash
$ fibratus capture -o my-capture
```

---

## Filtering during capture

You can restrict which events are recorded by providing a **filter expression**:

```bash
$ fibratus capture kevt.category = 'file' -o fs-events
```

This is useful for:

* Reducing capture size
* Focusing on specific subsystems (file, registry, network, etc.)
* Minimizing noise during analysis

> 💡 Filtering at capture time is more efficient than filtering during replay when dealing with high event volumes.

---

## Capture format and internals

Under the hood, captures are stored as **Zstandard (zstd)** compressed streams.

* Provides a strong balance between:

  * Compression ratio
  * Runtime overhead

### File structure

A `.kcap` file consists of:

1. **Header**

   * Magic (`kcap`)
   * Major/minor version
   * Flags

2. **Handle snapshot**

   * All active kernel handles at capture start

3. **Event stream**

   * Ordered kernel events

The **process state is not explicitly stored**. Instead, it is reconstructed during replay by processing events such as process enumeration and lifecycle notifications.

---

## Replaying captures

Replaying a capture restores system state and reprocesses events as if they were happening in real time.

```bash
$ fibratus replay -k events
```

During replay:

* Process and handle state are rebuilt
* Events are emitted through the same pipeline as live data
* Filters, rules, and filaments can be applied

---

### Version compatibility

Fibratus increments the **major version** of the `.kcap` format when breaking changes are introduced.

* Captures with mismatched major versions **may not replay**
* Always ensure compatibility between:

  * Capture producer version
  * Replay version

---

## Filtering during replay

You can apply filters when replaying to focus on relevant events:

```bash
$ fibratus replay file.name contains 'Temp' -k fs-events
```

This allows you to:

* Drill down into specific behaviors
* Iterate quickly during investigations
* Avoid re-capturing data

---

## Running filaments on captures

Captures can be used as input for **filaments**, enabling offline analytics and automation.

```bash
$ fibratus replay -f watch_files -k fs-events
```

This is particularly useful for:

* Testing filaments against real-world data
* Building detection pipelines without live telemetry
* Replaying known attack scenarios

---

## Practical workflows

### Malware analysis workflow

1. Run capture on sandbox:

```bash
$ fibratus capture -o malware-run
```

2. Execute suspicious sample
3. Stop capture
4. Transfer `.kcap` file to analysis machine
5. Replay with filters or filaments:

```bash
$ fibratus replay -k malware-run
```

---

### Detection development workflow

1. Capture real activity
2. Replay with experimental filters:

```bash
$ fibratus replay "ps.name = 'powershell.exe'" -k events
```

3. Convert filters into rules
4. Iterate quickly without re-capturing

---

## Best practices

* Use **filters during capture** to reduce noise and file size
* Keep captures **short and focused** for easier analysis
* Store captures from **real attack scenarios** for regression testing
* Ensure **version compatibility** before replaying old captures
* Use captures to **validate sequence rules and correlations**

---

## Summary

Captures are a foundational feature of Fibratus that enable:

* Deterministic replay of system activity
* Deep offline investigation
* Rapid iteration on detection logic

They bridge the gap between **live telemetry** and **repeatable analysis**, making them indispensable for security research and engineering workflows.

---

If you want, I can also add a section on **performance characteristics (capture overhead, disk throughput, buffering)** or **best practices for large-scale capture management**, which becomes important in production environments.


##### Captures fils contain the full state of processes at the time capture was taken as well as the originated event flux. This makes them a great companion in post-mortem investigations - generate the capture in the honeypot machine, grab the `.kcap` file, and you're ready to dive into the attacker kill chain by replaying the capture file on your laptop.

With captures you "freeze" the shape of the event flux at a certain point in time. Do you need to troubleshoot an network issue and surface the root cause? Or maybe you need to determine what files were written by a malicious process? Replay the capture at any given time and drill down into the event flow to start investigating.

You can harness the power of the filtering engine when replaying captures or even execute a filament on top of captured events.

## Capturing

Under the hood, captures are written to disk in the form of the [zstd](https://en.wikipedia.org/wiki/Zstandard) compressed streams. zstd provides a compelling balance between the capture file size and the compression runtime overhead.

Each capture file consists of the header that represents the `kcap` magic, major/minor version, and some arbitrary flags. Next, the handle snapshot is stored with all allocated handles followed by kernel events. We can forgo persisting the process snapshot, because it can be reconstructed when replaying the capture and processing the `EnumProcess` events.

Capturing is initiated by running the `fibratus capture` command. The `o` flag, that stands for `output`, specifies the `kcap` file where events are dumped. The capture file is stored in the current working directory. **Any already existing file is overwritten**. To above command would produce a capture and store all events in `events.kcap` file.

```
$ fibratus capture -o events
```

To stop capturing events, hit the `Ctrl-C` key combination. A short summary is displayed indicating the number of captured events, processes, handles, the size of the `kcap` file and so on.

### Filtering 

As already explained in [filtering](/filters/filtering), for a fine-grained control over which events are stored in the capture, you can provide a filter expression.

```
$ fibratus capture kevt.category = 'file' -o fs-events
```

## Replaying

Replaying essentially recovers the handle/process state and consumes the captured event flux. It is important to point out that Fibratus increments the major `kcap` version under relevant changes in the format structure. Because of this, old capture files might not be able to replay due to mismatch of the `kcap` major version digit.

To replay the `kcap` file, you launch the following command.

```
$ fibratus replay -k events
```

### Filtering 

To drill down into capture by filtering out valuable events, you can provide a filter.

```
$ fibratus replay file.name contains 'Temp' -k fs-events
```

### Filaments 

Another compelling use case stems from running a filament on top of events living in the capture. To run a filament you supply the filament name via the `-f` or `--filament.name` option.

```
$ fibratus replay -f watch_files -k fs-events
```
