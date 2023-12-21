//go:build yara
// +build yara

/*
 * Copyright 2020-2021 by Nedim Sabic Sabic
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

package yara

const alertTextTmpl = `
	{{ if .PS }}
	Possible malicious process, {{ .PS.Name }} ({{ .PS.PID }}), detected at {{ .Timestamp }}.

	Rule matches
	{{- with .Matches }}
	{{ range . }}
		Rule: {{ .Rule }}
		Namespace: {{ .Namespace }}
		Metas: {{ .Metas }}
		Tags: {{ .Tags }}
	{{ end }}
	{{- end }}

	Process information

	Name: 		{{ .PS.Name }}
	PID:  		{{ .PS.PID }}
	PPID: 		{{ .PS.Ppid }}
	Cmdline:	{{ .PS.Cmdline }}
	Cwd:		{{ .PS.Cwd }}
	SID:		{{ .PS.SID }}
	Session ID: {{ .PS.SessionID }}
	{{ if .PS.Envs }}
	Env:
			{{- with .PS.Envs }}
			{{- range $k, $v := . }}
			{{ $k }}: {{ $v }}
			{{- end }}
			{{- end }}
	{{ end }}
	Threads:
			{{- with .PS.Threads }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
	Modules:
			{{- with .PS.Modules }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
	{{ if .PS.Handles }}
	Handles:
			{{- with .PS.Handles }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
	{{ end }}

	{{ if .PS.PE }}
	Entrypoint:  		{{ .PS.PE.EntryPoint }}
	Image base: 		{{ .PS.PE.ImageBase }}
	Build date:  		{{ .PS.PE.LinkTime }}

	Number of symbols: 	{{ .PS.PE.NumberOfSymbols }}
	Number of sections: {{ .PS.PE.NumberOfSections }}

	Sections:
			{{- with .PS.PE.Sections }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
	{{ if .PS.PE.Symbols }}
	Symbols:
			{{- with .PS.PE.Symbols }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
	{{ end }}
	{{ if .PS.PE.Imports }}
	Imports:
			{{- with .PS.PE.Imports }}
			{{- range . }}
			{{ . }}
			{{- end }}
			{{- end }}
	{{ end }}
	{{ if .PS.PE.VersionResources }}
	Resources:
			{{- with .PS.PE.VersionResources }}
			{{- range $k, $v := . }}
			{{ $k }}: {{ $v }}
			{{- end }}
			{{- end }}
	{{ end }}
	{{ end }}

	{{ else }}

	Possible malicious file, {{ .Filename }}, detected at {{ .Timestamp }}.

	Rule matches
	{{ with .Matches }}
	{{ range . }}
		Rule: {{ .Rule }}
		Namespace: {{ .Namespace }}
		Metas: {{ .Metas }}
		Tags:  {{ .Tags }}
	{{ end }}
	{{ end }}

	{{ end }}
`
