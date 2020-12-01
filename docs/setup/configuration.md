# Configuration

You can parametrize Fibratus from various configuration sources including `yaml`/`json` files, environment variables and command line flags.
Properties that you specify via command line flags or environment variables take precedence over the configuration file.

### Files {docsify-ignore}

By default, configuration files are stored in `%PROGRAM FILES%\Fibratus\Config` directory. If you prefer to keep them in a different location, you can override the configuration file path via the `--config-file` command line flag when starting Fibratus. The template, `fibratus.yml` configuration file with all options documented is available in the `%PROGRAM FILES%\Fibratus\Config` directory.

### Flags {docsify-ignore}

Each CLI command accepts a set of config flags. For example, running the `fibratus run -h` command displays flag names, their default value (if any), and a short description. Command line flags take precedence over environment variables and configuration files.

!> Some configuration options are not exposed via command line flags and can only be tuned in the configuration file.


### Environment variables {docsify-ignore}

To set a certain configuration property via an environment variable, a simple rule of thumb needs to be followed: remove the leading `--` characters in the flag name, convert all `.` and `-` characters to `_` symbol, capitalize the environment variable name and you're ready to go.

Let's suppose we want to set the value of the `--kstream.buffer-size` flag via an environment variable. The resulting environment variable would get converted to `KSTREAM_BUFFER_SIZE`.
