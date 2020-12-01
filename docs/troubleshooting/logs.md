# Logs

Fibratus logs various diagnostics and error messages to log files residing in the `%PROGRAM FILES%\Fibratus\Logs` directory. Logs serve as an invaluable resource for debugging or chasing down issues in Fibratus.

### Configuration {docsify-ignore}

It's possible to influence the behavior of how log file are written. The configuration options are stored in the `logging` section of the `yml` file.

#### level

Specifies the minimum allowed log level. Anything logged below this log level will not get dumped to a file or stdout stream. Possible values are `debug`, `info`, `warn`, `error`, `panic`.

**default**: `info`

#### max-age

Represents the maximum number of days to retain old log files based on the timestamp encoded in their filename. By default, all log files are retained.

**default**: `0`

#### max-backup

Specifies the maximum number of old log files to retain.

**default**: `15`

#### max-size

Specifies the maximum size in megabytes of the log file before it gets rotated.

**default**: `100`

#### formatter

Represents the log file format. Possible values are `text` or `json`. By default, Fibratus will dump the logs in JSON format.

**default**: `json`

#### path

Represents the alternative paths for storing the logs.

#### log-stdout

Indicates whether log lines are written to standard output in addition to writing them to log files.

**default**: `false`
