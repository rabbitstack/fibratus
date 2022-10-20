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

package kevent

import (
	"bytes"
	"fmt"
	"text/template"
)

// Template is the default Go template used for formatting events.
var Template = `Name:  		{{ .Kevt.Name }}
Sequence: 		{{ .Kevt.Seq }}
Process ID:		{{ .Kevt.PID }}
Thread ID: 		{{ .Kevt.Tid }}
Params:			{{ .Kevt.Kparams }}

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
`

// RenderDefaultTemplate returns the event string representation
// after applying the default Go template.
func (kevt *Kevent) RenderDefaultTemplate() ([]byte, error) {
	tmpl, err := template.New("event").Parse(Template)
	if err != nil {
		return nil, err
	}
	return renderTemplate(kevt, tmpl)
}

// RenderCustomTemplate returns the event string representation
// after applying the given Go template.
func (kevt *Kevent) RenderCustomTemplate(tmpl *template.Template) ([]byte, error) {
	return renderTemplate(kevt, tmpl)
}

func renderTemplate(kevt *Kevent, tmpl *template.Template) ([]byte, error) {
	var writer bytes.Buffer
	data := struct {
		Kevt             *Kevent
		SerializeHandles bool
		SerializeThreads bool
		SerializeImages  bool
		SerializeEnvs    bool
		SerializePE      bool
	}{
		kevt,
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
