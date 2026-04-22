# Troubleshooting

## Logs

Fibratus logs various diagnostics and error messages to log files residing in the `%PROGRAM FILES%\Fibratus\Logs` directory. Logs serve as an invaluable resource for debugging or chasing code bugs.

It's possible to influence the behavior of how log file are written. The configuration options are stored in the `logging` section of the `yml` file.

### `level`

Specifies the minimum allowed log level. Anything logged below this log level will not get dumped to a file or stdout stream. Possible values are `debug`, `info`, `warn`, `error`, `panic`.

### `max-age`

Represents the maximum number of days to retain old log files based on the timestamp encoded in their filename. By default, all log files are retained.


### `max-backup`

Specifies the maximum number of old log files to retain.


### `max-size`

Specifies the maximum size in megabytes of the log file before it gets rotated.

### `formatter`

Represents the log file format. Possible values are `text` or `json`. By default, Fibratus will dump the logs in JSON format.


### `path`

Represents the alternative paths for storing the logs.

### `log-stdout`

Indicates whether log lines are written to standard output in addition to writing them to log files.


## Profiling

[pprof](https://golang.org/pkg/net/http/pprof/) is an extremely useful profiling facility that lets you collect CPU profiles, traces and heap allocation profiles among others. With `pprof` it is easy to spot top CPU consumers or find opportunities for code optimizations.

To get the profile, you can use the `go tool pprof` tool. The pprof HTTP handlers are exposed on `localhost:8482` by default. To override the TCP port or the transport protocol, modify the `api.transport` configuration option. For example, getting the CPU profile could be accomplished with the following command:

<Terminal>
$ go tool pprof http://localhost:8482/debug/pprof/profile

</Terminal>

The profile can be saved to the disk by typing `proto` in the interactive `pprof` CLI.

## Stats

Sometimes you need to go beyond surface-level visibility and understand how Fibratus itself is behaving under the hood. Especially when troubleshooting performance issues, validating pipeline behavior, or tuning rules. For that, Fibratus exposes a rich set of internal telemetry and runtime metrics.

These metrics are made available via Go’s [expvar](https://golang.org/pkg/expvar/) interface, which provides a lightweight, structured way to inspect counters, gauges, and other runtime values directly from within the application.

To quickly explore the metrics, you can use the built-in CLI command:

<Terminal>
$ fibratus stats

</Terminal>

This command surfaces a snapshot of Fibratus’ internal state, including event throughput, queue depths, dropped events, and other operational signals. It’s particularly useful for:

* Diagnosing bottlenecks in event processing pipelines
* Verifying that filters and rules are behaving as expected
* Monitoring resource utilization trends over time
* Gaining confidence in system stability during high event volumes

Because these metrics are exposed via [expvar](https://golang.org/pkg/expvar/), they can also be integrated with external observability tools or scraped programmatically, making it easier to incorporate Fibratus into a broader monitoring and alerting ecosystem.
