## CLI {docsify-ignore}

Invoking the `fibratus` binary without any parameters reveals available CLI commands. You can obtain help information for each available command by appending the `--help` or `-h` option after the command name. Let's briefly describe available commands.

### run

The main command for bootstrapping Fibratus (either in rule engine or event forwarder mode) or running a filament. It accepts an optional filter expression. Examples:

- collect all events
  ```
  $ fibratus run --forward
  ```

- run the `watch_files` filament
  ```
  $ fibratus run -f watch_files
  ```

- collect fs events originated from the `cmd.exe` process
  ```
  $ fibratus run --forward kevt.category = 'file' and ps.name = 'cmd.exe'
  ```

- collect fs events and enable PE introspection
  ```
  $ fibratus run --forward kevt.category = 'file' --pe.enabled=true
  ```

### capture

Dumps the event flow to specialized kcap (capture) file. It accepts an optional filter expression. Examples:

- capture all events to `events.kcap` capture file
  ```
  $ fibratus capture -o events
  ```

- capture network events from the specific destination IP address
  ```
  $ fibratus capture kevt.category = 'net' and net.dip = 172.17.2.3 -o events
  ```

### replay

Replays the event flow from the kcap file. It accepts an optional filter expression. Examples:

- replay all events from the `events.kcap` capture file
  ```
  $ fibratus replay -k events
  ```

- replay events that contain a specific resource name in the PE resource directory
  ```
  $ fibratus replay pe.resources[Company] contains 'blackwater' -k events
  ```

### rules

The root command that exposes various subcommands for listing/validating rules and creating detection rule templates.

- #### list

List all rules present in the `Rules` directory.

- #### validate

Validates rules for structural and syntactic correctness.

- #### create

Create a new rule template. The command requires a rule name and an optional MITRE tactic identifier (e.g. `TA0001`) that can be passed via `--tactic-id` flag.

### config

Prints the options loaded from configuration sources including files, command line flags or environment variables. Sensitive data, such as passwords are  masked out.

### service

This is the root command that exposes multiple subcommands for interacting with the **Windows Service Control Manager**.

- #### start

Starts the Fibratus service that was previously registered within the Windows Service Control Manager.

- #### stop

Stops the Fibratus Windows service.

- #### restart

Restarts the Fibratus Windows service.

- #### remove

Removes the Fibratus service from the Windows Service Control Manager.

- #### status

Checks the status of the Fibratus Windows service.

### docs

Launches the default web browser and opens the Fibratus documentation site.

### list

The command consists of various subcommands:

- #### filaments 

Displays available filaments. Filaments live in the `%PROGRAMFILES\Fibratus\Filaments` directory, but you can override this location with the `--filament.path` flag or the corresponding key in the `yaml` configuration file.

- #### fields 

Shows all [field names](/filters/fields) that can be used in filter expressions.

- #### kevents 

Shows available event types.

### stats

Returns the runtime metrics that are exposed through the [expvar](https://golang.org/pkg/expvar/) HTTP endpoint. Useful for debugging.

### version

Displays the Fibratus version along with the commit hash and the Go compiler version.
