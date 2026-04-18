# Console

##### The console is the default output sink. It renders incoming events directly to standard output, providing a real-time view of the event stream. To improve performance, the console output is buffered, reducing the number of I/O system calls required to write event data.

## Configuration

The console output configuration is located in the `outputs.console` section.

### `enabled`

Indicates whether the console output is active.

### `format`

Specifies the console output format. The `pretty` format dictates that formatting is accomplished by replacing the specifiers in the template. The `json` format outputs the event as a raw JSON string.

### `kv-delimiter`

Specifies the separator rendered between the event parameter's key and its value.


### `template`

Defines the template used in the event formatter. For more details, see the next section.

## Templates

The template consists of a collection of named placeholders that event formatter replaces with desired values. The syntax of the template resembles the Go [template](https://golang.org/pkg/text/template/) engine constructs, excepts the event formatter lacks advanced templating features such as loops, functions or `if` statements.

The following field modifiers are supported:

- `.Seq`
- `.Timestamp`
- `.Pid`
- `.Ppid`
- `.Pexe`
- `.Pcmd`
- `.Pname`
- `.Cwd`
- `.Exe`
- `.Cmd`
- `.Tid`
- `.Sid`
- `.Process`
- `.Category`
- `.Description`
- `.CPU`
- `.Type`
- `.Params`
- `.Meta`
- `.Host`
- `.PE`
- `.Params.`
- `.Callstack`

The default template is defined as:

```
{{ .Seq }} {{ .Timestamp }} - {{ .CPU }} {{ .Process }} ({{ .Pid }}) - {{ .Type }} ({{ .Params }})
```


