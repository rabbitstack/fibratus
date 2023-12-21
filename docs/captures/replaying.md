# Replaying

Replaying essentially recovers the handle/process state and consumes the captured event flux. It is important to point out that Fibratus increments the major `kcap` version under relevant changes in the format structure. Because of this, old capture files might not be able to replay due to mismatch of the `kcap` major version digit.

To replay the `kcap` file, you launch the following command.

```
$ fibratus replay -k events
```

### Filtering {docsify-ignore}

To drill down into capture by filtering out valuable events, you can provide a filter.

```
$ fibratus replay file.name contains 'Temp' -k fs-events
```

### Filaments {docsify-ignore}

Another compelling use case stems from running a filament on top of events living in the capture. To run a filament you supply the filament name via the `-f` or `--filament.name` option.

```
$ fibratus replay -f watch_files -k fs-events
```
