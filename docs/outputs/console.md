# Console

Console is the default output. It renders the inbound event flow onto the console. The console output tends to reduce the number of I/O syscalls by buffering the incoming event lines.

### Configuration {docsify-ignore}

The console output configuration is located in the `outputs.console` section.

#### enabled

Indicates whether the console output is active.

**default**: `true`

#### format

Specifies the console output format. The `pretty` format dictates that formatting is accomplished by replacing the specifiers in the template. The `json` format outputs the event as a raw JSON string.

**default**: `pretty`

#### kv-delimiter

Specifies the separator that's rendered between the event parameter's key and its value.

**default**: `➜`

#### template

Defines the template that's used in the event formatter. For more details, see the next section.

**default**: `{{ .Seq }} {{ .Timestamp }} - {{ .CPU }} {{ .Process }} ({{ .Pid }}) - {{ .Type }} ({{ .Kparams }})`

### Templates {docsify-ignore}

The template consists of a collection of named placeholders that event formatter replaces with desired values. The syntax of the template resembles the Go [template](https://golang.org/pkg/text/template/) engine constructs, excepts the event formatter lacks advanced templating features such as loops , functions or `if` statements.

The following field modifiers are supported:

- `.Seq`
- `.Timestamp`
- `.Pid`
- `.Ppid`
- `.Pexe`
- `.Pcomm`
- `.Pname`
- `.Cwd`
- `.Exe`
- `.Comm`
- `.Tid`
- `.Sid`
- `.Process`
- `.Category`
- `.Description`
- `.CPU`
- `.Type`
- `.Kparams`
- `.Meta`
- `.Host`
- `.PE`
- `.Kparams.`
- `.Callstack`

**Examples**

- `{{ .Type }} on file ({{ .Kparams.File_name }})`

  renders

  `CreateFile on file C:\ProgramData\AVG\Antivirus\psi.db-journal`

- `{{ .Seq }} {{ .Process }} ({{ .Cwd }}) {{ .Ppid }} ({{ .Sid }})`

  renders

  `1999 cmd.exe (C:/Windows/System32) 2324 (nedo/archrabbit)`

- `{{ .Seq }} {{.CPU}} -  ({{.Type}}) Pid: {{ .Kparams.Pid }} {{ .Meta }}`

  renders

  `1999 4 -  (CreateProcess) Pid: 1232 env: prod, az: east`
