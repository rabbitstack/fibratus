# CLI 

### `run`

The primary command for starting Fibratus-whether running the rule engine, operating as an event forwarder, or executing a filament. It also accepts an optional filter expression. Examples:

1. Collect all events

<Terminal>
$ fibratus run --forward

</Terminal>

2. Run a filament

<Terminal>
$ fibratus run -f watch_files

</Terminal>

3. Collect and filter events

<Terminal>
$ fibratus run --forward evt.category = 'file' and ps.name = 'cmd.exe'

</Terminal>

### `capture`

Writes the event stream to capture files. It accepts an optional filter expression. Example:

<Terminal>
$ fibratus capture evt.category = 'net' and net.dip=172.17.2.3 -o events

</Terminal>

### `replay`

Reconstructs the event stream from the capture file. It accepts an optional filter expression. Example:

<Terminal>
$ fibratus replay net.sip=172.2.2.3 -k events

</Terminal>

### `rules`

The root command that exposes various subcommands for listing/validating rules and creating detection rule templates.

- #### `list`

List all rules located in the `Rules` directory.

- #### `validate`

Validates rules for structural and syntactic correctness.

- #### `create`

Create a new rule template. The command requires a rule name and an optional MITRE tactic identifier, for example `TA0001`, that can be passed via the `--tactic-id` flag.

### `config`

Prints the options loaded from configuration sources including files, command line flags or environment variables. Sensitive data, such as passwords are masked out.

### `service`

This is the root command that exposes multiple subcommands for interacting with the Windows [Service Control Manager](https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager).

- #### `start`

Starts the Fibratus service that previously registered with the Windows Service Control Manager.

- #### `stop`

Stops the Fibratus Windows service.

- #### `restart`

Restarts the Fibratus Windows service.

- #### `remove`

Removes the Fibratus service from the Windows Service Control Manager.

- #### `status`

Checks the status of the Fibratus Windows service.

### `docs`

Launches the default web browser and opens the Fibratus documentation site.

### `list`

The command consists of various subcommands to list available filaments, event types or filter fields.

- #### `filaments`

Displays available filaments. Filaments live in the `%PROGRAMFILES\Fibratus\Filaments` directory, but you can override this location with the `--filament.path` flag or the corresponding key in the `yaml` configuration file.

- #### `fields`

Shows all [field names](rules/fields.md) that can be used in rule conditions.

- #### `events`

Shows available event types.

### `stats`

Returns the runtime metrics that are exposed through the [expvar](https://golang.org/pkg/expvar/) HTTP endpoint. Useful for debugging.

### `version`

Displays the Fibratus version along with the commit hash and the Go compiler version.

### `help`

Displays detailed usage information for commands, including available flags and options.
