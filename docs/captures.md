# Immortalizing The Event Flux

Captures or `kcap` files aim for the capture-once replay-anywhere workflow. Captures contain the full state of processes at the time capture was taken as well as the originated event flux. This makes them a great companion in post-mortem investigations - generate the capture in the honeypot machine, grab the `.kcap` file, and you're ready to dive into the attacker kill chain by replaying the capture file on your laptop.

With captures you "freeze" the shape of the event flux at a certain point in time. Do you need to troubleshoot an network issue and surface the root cause? Or maybe you need to determine what files were written by a malicious process? Replay the capture at any given time and drill down into the event flow to start investigating.

You can harness the power of the filtering engine when replaying captures or even execute a filament on top of captured events.

# Capturing

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

# Replaying

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
