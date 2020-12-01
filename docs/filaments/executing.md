# Executing Filaments

Filaments are bootstrapped via the `fibratus run` command by specifying the filament name. Use the `-f` or `--filament.name` flags to indicate the filament you'd like to run.

```
$ fibratus run -f watch_files
```

The filament will keep running until the keyboard interrupt signal is received. By default, filaments reside within the `%PROGRAMFILES%\Fibratus\Filaments` directory. It is possible to override this location by specifying an alternative directory via the `--filament.path` flag or by editing the config file.

To list available filaments, run the above command.

```
$ fibratus list filaments
```

### Filters {docsify-ignore}

Engaging filters in filaments can be accomplished in two ways:

- the command line argument when running the filament
- the `kfilter` function during filament initialization

If the filter expression is supplied in both the CLI argument and the `kfilter` function, the one set in the latter takes precedence.
