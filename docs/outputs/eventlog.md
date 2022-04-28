# Eventlog

Exports events via [Windows Event Log](https://docs.microsoft.com/en-us/windows/win32/wes/windows-event-log) API that can be explored with the [Event Viewer](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc766042(v=ws.11)) management tool. The screenshots below illustrate event logs produced by Fibratus. The `General` tab reveals the event type that was generated. Each log event pertains to the specific `Task Category` that directly maps to the internal event category. Similar to [sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon), Fibratus classifies each event with a custom `Event ID`. 

<p align="center">
  <img src="outputs/images/eventlog-general.png"/>
</p>

The `Details` tab shows extended event data including event parameters, process, and thread information. It is possible to customize the rendering template to influence the constructed event data. This is achieved by changing the [`eventlog.template`](outputs/eventlog?id=template) configuration property.

<p align="center">
  <img src="outputs/images/eventlog-details.png"/>
</p>

### Configuration {docsify-ignore}

The Eventlog output configuration is located in the `outputs.eventlog` section.

#### enabled

Indicates whether the Eventlog output is enabled.

**default**: `false`


#### level

Specifies the eventlog level associated with the event logs produced by Fibratus. You can specify one of the following values:

- `info`, `INFO`
- `warn`, `warning`, `WARN`, `WARNING`
- `erro`, `ERRO`, `error`, `ERROR`

**default**: `info`

#### remote-host

Address of the remote eventlog intake.

#### template

Go [template](https://pkg.go.dev/text/template) for rendering the eventlog message.

**default**:

```
Name:  		    {{ .Kevt.Name }}
Sequence: 		{{ .Kevt.Seq }}
Process ID:		{{ .Kevt.PID }}
Thread ID: 		{{ .Kevt.Tid }}
Cpu: 			{{ .Kevt.CPU }}
Params:			{{ .Kevt.Kparams }}
Category: 		{{ .Kevt.Category }}

{{- if .Kevt.PS }}

Process:		{{ .Kevt.PS.Name }}
Exe:			{{ .Kevt.PS.Exe }}
Pid:  			{{ .Kevt.PS.PID }}
Ppid: 			{{ .Kevt.PS.Ppid }}
Cmdline:		{{ .Kevt.PS.Comm }}
Cwd:			{{ .Kevt.PS.Cwd }}
SID:			{{ .Kevt.PS.SID }}
Session ID:		{{ .Kevt.PS.SessionID }}
{{ if and (.SerializeEnvs) (.Kevt.PS.Envs) }}
Env:
			{{- with .Kevt.PS.Envs }}
			{{- range $k, $v := . }}
			{{ $k }}: {{ $v }}
			{{- end }}
			{{- end }}
{{ end }}
{{ if .SerializeThreads }}
Threads:
			{{- with .Kevt.PS.Threads }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ end }}
{{ if .SerializeImages }}
Modules:
			{{- with .Kevt.PS.Modules }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ end }}
{{ if and (.SerializeHandles) (.Kevt.PS.Handles) }}
Handles:
			{{- with .Kevt.PS.Handles }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ end }}

{{ if and (.SerializePE) (.Kevt.PS.PE) }}
Entrypoint:  		{{ .Kevt.PS.PE.EntryPoint }}
Image base: 		{{ .Kevt.PS.PE.ImageBase }}
Build date:  		{{ .Kevt.PS.PE.LinkTime }}

Number of symbols: 	{{ .Kevt.PS.PE.NumberOfSymbols }}
Number of sections: {{ .Kevt.PS.PE.NumberOfSections }}

Sections:
			{{- with .Kevt.PS.PE.Sections }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ if .Kevt.PS.PE.Symbols }}
Symbols:
			{{- with .Kevt.PS.PE.Symbols }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ end }}
{{ if .Kevt.PS.PE.Imports }}
Imports:
			{{- with .Kevt.PS.PE.Imports }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ end }}
{{ if .Kevt.PS.PE.VersionResources }}
Resources:
			{{- with .Kevt.PS.PE.VersionResources }}
			{{- range $k, $v := . }}
			{{ $k }}: {{ $v }}
			{{- end }}
			{{- end }}
			{{ end }}
{{ end }}
{{- end }}

```
