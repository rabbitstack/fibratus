/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
 * https://www.fibratus.io
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package event

import (
	"bytes"
	"fmt"
	"text/template"
)

// Template is the default Go template used for formatting events in textual format.
var Template = `Name:  		{{ .Evt.Name }}
Sequence: 		{{ .Evt.Seq }}
Description:    {{ .Evt.Description }}
Process ID:		{{ .Evt.PID }}
Thread ID: 		{{ .Evt.Tid }}
Params:			{{ .Evt.Params }}

{{- if .Evt.PS }}

Process:		{{ .Evt.PS.Name }}
Exe:			{{ .Evt.PS.Exe }}
Pid:  			{{ .Evt.PS.PID }}
Ppid: 			{{ .Evt.PS.Ppid }}
Cmdline:		{{ .Evt.PS.Cmdline }}
Cwd:			{{ .Evt.PS.Cwd }}
SID:			{{ .Evt.PS.SID }}
User:           {{ .Evt.PS.Username }}
Domain:         {{ .Evt.PS.Domain }}
Session ID:		{{ .Evt.PS.SessionID }}
{{ if and (.SerializeEnvs) (.Evt.PS.Envs) }}
Env:
			{{- with .Evt.PS.Envs }}
			{{- range $k, $v := . }}
			{{ $k }}: {{ $v }}
			{{- end }}
			{{- end }}
{{ end }}
{{ if .SerializeThreads }}
Threads:
			{{- with .Evt.PS.Threads }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ end }}
{{ if .SerializeImages }}
Modules:
			{{- with .Evt.PS.Modules }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ end }}
{{ if and (.SerializeHandles) (.Evt.PS.Handles) }}
Handles:
			{{- with .Evt.PS.Handles }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ end }}

{{ if and (.SerializePE) (.Evt.PS.PE) }}
Entrypoint:  		{{ .Evt.PS.PE.EntryPoint }}
Image base: 		{{ .Evt.PS.PE.ImageBase }}
Build date:  		{{ .Evt.PS.PE.LinkTime }}

Number of symbols: 	{{ .Evt.PS.PE.NumberOfSymbols }}
Number of sections: {{ .Evt.PS.PE.NumberOfSections }}

Sections:
			{{- with .Evt.PS.PE.Sections }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ if .Evt.PS.PE.Symbols }}
Symbols:
			{{- with .Evt.PS.PE.Symbols }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ end }}
{{ if .Evt.PS.PE.Imports }}
Imports:
			{{- with .Evt.PS.PE.Imports }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
{{ end }}
{{ if .Evt.PS.PE.VersionResources }}
Resources:
			{{- with .Evt.PS.PE.VersionResources }}
			{{- range $k, $v := . }}
			{{ $k }}: {{ $v }}
			{{- end }}
			{{- end }}
			{{ end }}
{{ end }}
{{- end }}
`

// RenderDefaultTemplate returns the event string representation
// after applying the default Go template.
func (e *Event) RenderDefaultTemplate() ([]byte, error) {
	tmpl, err := template.New("event").Parse(Template)
	if err != nil {
		return nil, err
	}
	return renderTemplate(e, tmpl)
}

// RenderCustomTemplate returns the event string representation
// after applying the given Go template.
func (e *Event) RenderCustomTemplate(tmpl *template.Template) ([]byte, error) {
	return renderTemplate(e, tmpl)
}

func renderTemplate(evt *Event, tmpl *template.Template) ([]byte, error) {
	var writer bytes.Buffer
	data := struct {
		Evt              *Event
		SerializeHandles bool
		SerializeThreads bool
		SerializeImages  bool
		SerializeEnvs    bool
		SerializePE      bool
	}{
		evt,
		SerializeHandles,
		SerializeThreads,
		SerializeImages,
		SerializeEnvs,
		SerializePE,
	}
	err := tmpl.Execute(&writer, data)
	if err != nil {
		return nil, fmt.Errorf("unable to render event template: %v", err)
	}
	return writer.Bytes(), nil
}
