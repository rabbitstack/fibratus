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

package mail

var htmlTemplate = `
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
  <style>
     @media only screen and (max-width: 600px) {
      .alert-body-inner,
      .alert-footer {
        width: 100% !important;
      }
    }
  </style>
  <!--[if (gte mso 9)|(IE)]>
    <style type="text/css">
        table {border-collapse: collapse;}
    </style>
  <![endif]-->
  <title></title>
</head>
<body style="font-family: 'Noto Sans', Tahoma, Roboto, 'Open Sans', Arial, 'Helvetica Neue', Helvetica, sans-serif; -webkit-box-sizing: border-box; box-sizing: border-box; width: 100% !important; height: 100%; margin: 0; line-height: 1.4; background-color: #f7f7f7; color: #74787E; -webkit-text-size-adjust: none; border-radius: 4px">
<table style="width: 100%; margin: 0; padding: 0; background-color: #F2F4F6; border-collapse: collapse;" width="100%" cellpadding="0" cellspacing="0">
  <tr>
    <td>
      <table style="width: 100%; margin: 0px; padding: 0; border-collapse: collapse;" width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="width: 100%; margin: 0; padding: 0; align: center" width="100%">
            <table class="alert-body-inner" style="width: 570px; margin: 0 auto; padding: 0; border-collapse: collapse;" align="center" width="570" cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding: 35px; color: #74787E; font-size: 15px; line-height: 18px;">
                  <p style="font-size: 12px; color: #C5C5C5; line-height: 0.5em;">
                    Triggered on <span style="color: #6f7578;">{{ .TriggeredAt | date "Mon Jan 02 2006" }} at {{ .TriggeredAt | date "03:04:05 PM" }}</span> in <span
                    style="color: #6f7578;"> {{ .Hostname }} </span> host
                  </p>
                  <h1 style="font-size: 16px; font-weight: bold; color: #2F3133; text-decoration: none; text-shadow: 0 1px 0 white;">{{ .Alert.Title }}</h1>
                  {{- if .Alert.Text }}
                  <div style="margin-bottom: 5px;">
                  {{- else }}
                  <div style="margin-bottom: 10px;">
                  {{- end }}
                      {{ $severityColor := "#fcd834" }}
                      {{- if eq .Alert.Severity.String "low" }}
                      {{ $severityColor := "#29b33e" }}
                      {{- else if eq .Alert.Severity.String "medium" }}
                      {{ $severityColor := "#fcd834" }}
                      {{- else }}
                      {{ $severityColor = "#fa7975" }}
                      {{- end }}
                      <span style="height: 8px; width: 8px; border-radius: 50%; display: inline-block; background-color: {{ $severityColor }}"></span>
                      <p style="font-size: 12px; white-space: pre-wrap; color: #6f7578; line-height: 0.5em; display: inline; margin-left: 2px">{{ .Alert.Severity.String | title }} Severity</p>
                  </div>
                  {{- if .Alert.Text }}
                  {{ $text := (regexReplaceAll "<code>" .Alert.Text "<code style='border-radius: 5px; color: #404243; font-size: .8rem; margin: 0 2px; padding: 3px 5px; line-height: 1.7rem; white-space: pre-wrap; font-weight: 600; font-family: Consolas, Roboto, monaco, monospace; background-color: #e1e3e4;'>") }}
                  <p style="font-size: .8rem; margin: 0 0 4px 0px; padding: 3px 0px; white-space: pre-wrap; line-height: 1.5em;">{{ regexReplaceAll "\\s+" $text " " }}</p>
                  {{- end }}
                  {{ if hasKey .Alert.Labels "tactic.name" }}
                  <div class="tag" style="display: inline-block; border-radius: 5px; color: #404243; font-size: .8rem; margin: 2px 2px; padding: 3px 5px; white-space: pre-wrap; font-weight: 600; background-color: #bad1fb;"><a style="text-decoration: none; color: inherit;" href="{{ index .Alert.Labels "tactic.ref"}}">{{ index .Alert.Labels "tactic.name"}}</a></div>
                  {{ end }}
                  {{ if hasKey .Alert.Labels "technique.name" }}
                  <div class="tag" style="display: inline-block; border-radius: 5px; color: #404243; font-size: .8rem; margin: 2px 2px; padding: 3px 5px; white-space: pre-wrap; font-weight: 600; background-color: #84cad7;"><a style="text-decoration: none; color: inherit;" href="{{ index .Alert.Labels "technique.ref"}}">{{ index .Alert.Labels "technique.name"}}</a></div>
                  {{ end }}
                  {{ if hasKey .Alert.Labels "subtechnique.name" }}
                  <div class="tag" style="display: inline-block; border-radius: 5px; color: #404243; font-size: .8rem; margin: 2px 2px; padding: 3px 5px; white-space: pre-wrap; font-weight: 600; background-color: #fcbcba;"><a style="text-decoration: none; color: inherit;" href="{{ index .Alert.Labels "subtechnique.ref"}}">{{ index .Alert.Labels "subtechnique.name"}}</a></div>
                  {{ end }}
                </td>
              </tr>
             {{- if .Alert.Description }}
              <tr>
                <td style="padding: 5px 0px 0px 15px;">
                  <p style="background: #efefef; display: inline-block; border-radius: 5px; font-size: .8rem; margin: 4px 4px 25px 0px; padding: 3px 5px; white-space: pre-wrap; line-height: 1.5em;">
                     {{- .Alert.Description | trimSuffix "." }}
                  </p>
                </td>
              </tr>
			 {{ end }}
            </table>
          </td>
        </tr>

        <tr>
          <td style="width: 100%; margin: 0; padding: 0; background-color: #F2F4F6;" width="100%">
            <table class="alert-body-inner" style="width: 570px; margin: 0 auto; padding: 0; border-collapse: collapse;" align="center" width="570" cellpadding="0" cellspacing="0">
              <tr>
                <td style="padding: 35px;">
                  <h1 style="font-weight: bold; margin-bottom: 22px; margin-top: 0px; font-size: 16px;">
                    Security events involved in this incident
                  </h1>
                  {{- range $i, $evt := .Alert.Events }}
                  {{ with $evt }}
                  <table style="width: 100%; margin: 0; padding: 35px 0; border-collapse: collapse;" width="100%" cellpadding="0" cellspacing="0">
                    <tr>
                      <td>
                        <table style="width: 100%; margin: 0; padding: 35px 0;" width="100%" cellpadding="0" cellspacing="0">
                          <tr>
                            <td style="padding: 5px 0px 0px 35px;">
                              <div>
                                <h1 style="color: #A8A9A9; font-size: 22px; margin-top: 0; font-weight: bold;"><span style=font-style: italic;color: #C5C5C5; font-size: 28px;">#</span> {{ $i | add1 }}</h1>
                              </div>
                            </td>
                            <td>
                              <p style="color: #6f7c96; font-weight: bold; margin-top: 0px;">{{ .Name }}</p>
                              <p style="margin-top: -10px; font-size: 12px; color: #C5C5C5; line-height: 0.5em;"><span style="color: #A8A9A9;">{{ .Timestamp | date "03:04:05 PM" }}</span></p>
                            </td>
                          </tr>
                          <tr>
                            <td style="padding: 10px 5px; color: #74787E; font-size: 15px; line-height: 18px;" colspan="2">
                              {{ regexReplaceAll "<code>" .Summary "<code style='border-radius: 5px; color: #404243; font-size: .8rem; margin: 0 2px; padding: 3px 5px; line-height: 1.7rem; white-space: pre-wrap; font-weight: 600; font-family: Consolas, Roboto, monaco, monospace; background-color: #e1e3e4;'>" }}
                            </td>
                          </tr>
                          <tr>
                            <td colspan="2">
                              <table style="width: 100%; margin: 16px 0 16px 0;" width="100%" cellpadding="0" cellspacing="0">
                                {{- range $key, $par := .Kparams }}
                                <tr>
                                  <td style="padding: 5px 5px;">
                                    <span style="font-size: 13px; color: #626567;">{{ regexReplaceAll "_" $key " " | title }}</span>
                                  </td>
                                  <td style="padding: 5px 5px;">
                                    {{ $paramValue := $par.String }}
                                    <p style="margin: 4px 4px 4px 0px; font-size: 13px; color: #74787E; font-weight: bold; line-height: 1.1em; background: #fed5a0; display: inline-block; border-radius: 5px; padding: 3px 5px; white-space: pre-wrap;">{{ $paramValue }}</p>
                                  </td>
                                </tr>
                                {{- end }}
                              </table>
                            </td>
                          </tr>
                          {{- if .PS }}
                          <tr>
                            <td colspan="2">
                                <h2 style="margin-top: 0; color: #2F3133; font-size: 16px; font-weight: bold;">Process</h2>
                                <div style="align: center; padding: 0;">
                                  <table style="width: 100%; margin: 16px 0 16px 0;" width="100%" cellpadding="0" cellspacing="0">
                                    <tr>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #626567; line-height: 1.1em;">Pid</p>
                                      </td>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #74787E; line-height: 1.1em; font-weight: bold; display: inline-block; padding: 3px 5px; white-space: pre-wrap;">{{ .PS.PID }}</p>
                                      </td>
                                    </tr>
                                    <tr>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #626567; line-height: 1.1em;">Name</p>
                                      </td>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #74787E; line-height: 1.3em; font-weight: bold; display: inline-block; padding: 3px 5px; white-space: pre-wrap;">{{ .PS.Name }}</p>
                                      </td>
                                    </tr>
                                    <tr>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #626567; line-height: 1.1em;">Parent</p>
                                      </td>
                                      <td style="padding: 5px 5px;">
                                      {{- if .PS.Parent -}}
                                        <p style="margin-top: 0px; font-size: 13px; color: #74787E; line-height: 1.3em; font-weight: bold; display: inline-block; padding: 3px 5px; white-space: pre-wrap;">{{ .PS.Parent.Name }} ({{.PS.Parent.PID}})</p>
                                      {{- else -}}
                                        <p style="margin-top: 0px; font-size: 13px; color: #74787E; line-height: 1.3em; font-weight: bold; display: inline-block; padding: 3px 5px; white-space: pre-wrap;">N/A {{ .PS.Ppid }}</p>
                                      {{- end -}}
                                      </td>
                                    </tr>
                                    {{- if gt (len .PS.Ancestors) 1 }}
                                    <tr>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #626567; line-height: 1.1em;">Ancestors</p>
                                      </td>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #74787E; line-height: 1.3em; font-weight: bold; display: inline-block; padding: 3px 5px; white-space: pre-wrap;">{{ .PS.Ancestors | join " &#65125; " }}</p>
                                      </td>
                                    </tr>
                                    {{- end }}
                                    <tr>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #626567; line-height: 1.1em;">Exe</p>
                                      </td>
                                      <td style="padding: 5px 5px;">
                                        <p style="position: relative; margin-top: 0px; font-size: 13px; color: #74787E; line-height: 1.3em; font-weight: bold; display: inline-block; padding: 3px 5px; white-space: pre-wrap;">{{ .PS.Exe }}</p>
                                      </td>
                                    </tr>
                                    <tr>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #626567; line-height: 1.1em;">Cmdline</p>
                                      </td>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #74787E; line-height: 1.3em; font-weight: bold; display: inline-block; padding: 3px 5px; white-space: pre-wrap;">{{ .PS.Cmdline }}</p>
                                      </td>
                                    </tr>
                                    <tr>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #626567; line-height: 1.1em;">Cwd</p>
                                      </td>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #74787E; line-height: 1.3em; font-weight: bold; display: inline-block; padding: 3px 5px; white-space: pre-wrap;">{{ .PS.Cwd }}</p>
                                      </td>
                                    </tr>
                                    <tr>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #626567; line-height: 1.1em;">User</p>
                                      </td>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #74787E; line-height: 1.3em; font-weight: bold; display: inline-block; padding: 3px 5px; white-space: pre-wrap;">{{ .PS.SID }}</p>
                                      </td>
                                    </tr>
                                    <tr>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #626567; line-height: 1.1em;">Session ID</p>
                                      </td>
                                      <td style="padding: 5px 5px;">
                                        <p style="margin-top: 0px; font-size: 13px; color: #74787E; line-height: 1.3em; font-weight: bold; display: inline-block; padding: 3px 5px; white-space: pre-wrap;">{{ .PS.SessionID }}</p>
                                      </td>
                                    </tr>
                                  </table>
                                </div>
                            </td>
                          </tr>
                          {{- end }}
                        </table>
                      </td>
                    </tr>
                  </table>
                  {{- end }}
                  {{- end }}
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </td>
  </tr>
  <tr style="margin: 0 auto; padding: 0; text-align: center; background: #f7f7f7;">
    <td style="padding: 5px;">
      <p style="font-size: 9px; text-align: center;">
        This email was automatically generated by Fibratus {{ .Version }}
      </p>
    </td>
  </tr>
</table>
</body>
</html>
`
