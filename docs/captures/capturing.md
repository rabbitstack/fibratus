# Capturing

Under the hood, captures are written to disk in the form of the [zstd](https://en.wikipedia.org/wiki/Zstandard) compressed streams. zstd provides a compelling balance between the capture file size and the compression runtime overhead.

Each capture file consists of the header that represents the `kcap` magic, major/minor version, and some arbitrary flags. Next, the handle snapshot is stored with all allocated handles followed by kernel events. We can forgo persisting the process snapshot, because it can be reconstructed when replaying the capture and processing the `EnumProcess` events.

Capturing is initiated by running the `fibratus capture` command. The `o` flag, that stands for `output`, specifies the `kcap` file where events are dumped. The capture file is stored in the current working directory. **Any already existing file is overwritten**. To above command would produce a capture and store all events in `events.kcap` file.

```
$ fibratus capture -o events
```

To stop capturing events, hit the `Ctrl-C` key combination. A short summary is displayed indicating the number of captured events, processes, handles, the size of the `kcap` file and so on.

### Filtering {docsify-ignore}

As already explained in [filtering](/filters/filtering), for a fine-grained control over which events are stored in the capture, you can provide a filter expression.

```
$ fibratus capture kevt.category = 'file' -o fs-events
```
