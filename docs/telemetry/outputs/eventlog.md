# Eventlog

##### Exports events via [Windows Event Log](https://docs.microsoft.com/en-us/windows/win32/wes/windows-event-log) API that can be explored with the [Event Viewer](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc766042(v=ws.11)) management tool. Fibratus classifies each event with a custom `Event ID`

## Configuration 

The Eventlog output configuration is located in the `outputs.eventlog` section.

### `enabled`

Indicates whether the Eventlog output is enabled.

### `level`

Specifies the eventlog level associated with the event logs produced by Fibratus. You can specify one of the following values `info`, `INFO`, `warn`, `warning`, `WARN`, `WARNING`, `erro`, `ERRO`, `error`, `ERROR`

### `remote-host`

Address of the remote eventlog service.

### `template`

Custom Go [template](https://pkg.go.dev/text/template) for rendering the eventlog message.

