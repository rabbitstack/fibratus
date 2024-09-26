/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package config

import (
	"bytes"
	"text/template"
)

var schema = `
{
	"$schema": "http://json-schema.org/draft-07/schema#",
	"definitions": {"yara": {"$id": "#yara", "type": "object", "properties": {"enabled": {"type": "boolean"}}}},

	"type": "object",
	"properties": {
		"aggregator": {
			"type": "object",
			"properties": {
				"flush-period":		{"type": "string", "minLength": 2, "pattern": "[0-9]+ms|s"},
				"flush-timeout":	{"type": "string", "minLength": 2, "pattern": "[0-9]+s"}
			},
			"additionalProperties": false
		},
		"alertsenders": {
			"type": "object",
			"anyOf": [{
					"properties": {
						"mail": {
							"type": "object",
							"properties": {
								"enabled": 		{"type": "boolean"},
								"host": 		{"type": "string"},
								"port": 		{"type": "number"},
								"user": 		{"type": "string"},
								"password": 	{"type": "string"},
								"from": 		{"type": "string"},
								"to": 			{"type": "array", "items": {"type": "string", "format": "email"}},
								"content-type": {"type": "string"},
								"use-template": {"type": "boolean"}
							},
							"if": {
								"properties": {"enabled": { "const": true }}
							},
							"then": {
								"properties": {
									"from": {"type": "string", "format": "email"},
									"to": 	{"type": "array", "minItems": 1, "items": {"type": "string", "format": "email"}}
								}
							},
							"additionalProperties": false
						},
						"slack": {
							"type": "object",
							"properties": {
								"enabled": 		{"type": "boolean"},
								"url": 			{"type": "string"},
								"workspace": 	{"type": "string"},
								"channel": 		{"type": "string"},
								"emoji": 		{"type": "string"}
							},
							"if": {
								"properties": {"enabled": { "const": true }}
							},
							"then": {
								"properties": {"url": {"type": "string", "format": "uri", "minLength": 1, "pattern": "^(https?|http?)://"}}
							},
							"additionalProperties": false
						},
						"systray": {
							"type": "object",
							"properties": {
								"enabled": 		{"type": "boolean"},
								"sound": 		{"type": "boolean"},
								"quiet-mode": 	{"type": "boolean"}
							},
							"additionalProperties": false

						},
		                "eventlog": {
							"type": "object",
							"properties": {
								"enabled": {"type": "boolean"},
								"verbose": {"type": "boolean"}
							},
							"additionalProperties": false
						}
					},
					"additionalProperties": false
				}
			]
		},
		"api": {
			"type": "object",
			"properties": {
				"transport": 		{"type": "string", "minLength": 3},
				"timeout":			{"type": "string", "minLength": 2, "pattern": "[0-9]+s"}
			},
			"additionalProperties": false
		},
		"config-file": 						{"type": "string"},
		"debug-privilege":  				{"type": "boolean"},
		"forward":  						{"type": "boolean"},
		"symbol-paths":						{"type": "string"},
		"symbolize-kernel-addresses":		{"type": "boolean"},
		"handle": {
			"type": "object",
			"properties": {
				"init-snapshot": 		{"type": "boolean"},
				"enumerate-handles": 	{"type": "boolean"}
			},
			"additionalProperties": false
		},
		"kcap": {
			"type": "object",
			"properties": {
				"file":				{"type": "string"}
			},
			"additionalProperties": false
		},
		"filament": {
			"type": "object",
			"properties": {
				"name":				{"type": "string"},
				"path":				{"type": "string"},
				"flush-period":		{"type": "string",  "minLength": 2, "pattern": "[0-9]+ms|s"}
			},
			"additionalProperties": false
		},
		"filters": {
			"type": "object",
			"properties": {
				"rules": {
					"type": "object",
					"properties": {
						"enabled": 		{"type": "boolean"},
						"from-paths": 	{"type": ["array", "null"], "items": [{"type": "string", "minLength": 4}]},
						"from-urls":	{"type": ["array", "null"], "items": [{"type": "string", "minLength": 8}]}
					},
					"additionalProperties": false
				},
				"macros": {
					"type": "object",
                    "properties": {
                        "from-paths": 	{"type": ["array", "null"], "items": [{"type": "string", "minLength": 4}]}
                    },
                    "additionalProperties": false
                }
			},
			"additionalProperties": false
		},
		"kevent": {
			"type": "object",
			"properties": {
				"serialize-threads":	{"type": "boolean"},
				"serialize-images":		{"type": "boolean"},
				"serialize-handles":	{"type": "boolean"},
				"serialize-pe":			{"type": "boolean"},
				"serialize-envs":		{"type": "boolean"}
			},
			"additionalProperties": false
		},
		"kstream": {
			"type": "object",
			"properties": {
				"enable-thread": 	{"type": "boolean"},
				"enable-image": 	{"type": "boolean"},
				"enable-registry": 	{"type": "boolean"},
				"enable-fileio": 	{"type": "boolean"},
				"enable-vamap":		{"type": "boolean"},
				"enable-handle": 	{"type": "boolean"},
				"enable-net": 		{"type": "boolean"},
				"enable-mem": 		{"type": "boolean"},
				"enable-audit-api": {"type": "boolean"},
				"enable-dns": 		{"type": "boolean"},
				"stack-enrichment": {"type": "boolean"},
				"min-buffers": 		{"type": "integer", "minimum": 1, "maximum": {{ .MinBuffers }}},
				"max-buffers": 		{"type": "integer", "minimum": 2, "maximum": {{ .MaxBuffers }}},
				"buffer-size":		{"type": "integer", "maximum": {{ .MaxBufferSize }}},
                "flush-interval":	{"type": "string", "minLength": 2, "pattern": "[0-9]+s"},
				"blacklist":		{
					"type": "object",
					"properties":	{
						"events":	{"type": "array", "items": {"type": "string", "enum": ["CreateThread", "TerminateThread", "OpenProcess", "OpenThread", "SetThreadContext", "LoadImage", "UnloadImage", "CreateFile", "CloseFile", "ReadFile", "WriteFile", "DeleteFile", "RenameFile", "SetFileInformation", "EnumDirectory", "MapViewFile", "UnmapViewFile", "RegCreateKey", "RegOpenKey", "RegSetValue", "RegQueryValue", "RegQueryKey", "RegDeleteKey", "RegDeleteValue", "RegCloseKey", "Accept", "Send", "Recv", "Connect", "Disconnect", "Reconnect", "Retransmit", "CreateHandle", "CloseHandle", "DuplicateHandle", "QueryDns", "ReplyDns", "VirtualAlloc", "VirtualFree"]}},
						"images":	{"type": "array", "items": {"type": "string", "minLength": 1}}
					},
					"additionalProperties": false
				}
			},
			"additionalProperties": false
		},
		"logging": {
			"type": "object",
			"properties": {
				"level": 			{"type": "string"},
				"max-age":			{"type": "integer"},
				"max-backups":		{"type": "integer", "minimum": 1},
				"max-size":			{"type": "integer", "minimum": 1},
				"formatter":		{"type": "string", "enum": ["json", "text"]},
				"path":				{"type": "string"},
				"log-stdout":		{"type": "boolean"}
			},
			"additionalProperties": false
		},
		"output": {
			"type": "object",
			"anyOf": [{
					"properties": {
						"console": {
							"type": "object",
							"properties": {
								"enabled":		{"type": "boolean"},
								"format": 		{"type": "string", "enum": ["json", "pretty"]},
								"template": 	{"type": "string"},
								"kv-delimiter": {"type": "string"}
							},
							"additionalProperties": false
						},
						"elasticsearch": {
							"type": "object",
							"properties": {
								"enabled":					{"type": "boolean"},
								"servers": 					{"type": "array", "items": [{"type": "string", "minItems": 1, "format": "uri", "minLength": 1, "maxLength": 255, "pattern": "^(https?|http?)://"}]},
								"timeout": 					{"type": "string"},
								"index-name":				{"type": "string", "minLength": 1},
								"template-config":			{"type": "string"},
								"template-name":			{"type": "string", "minLength": 1},
								"healthcheck": 				{"type": "boolean"},
								"bulk-workers":				{"type": "integer", "minimum": 1},
								"sniff": 					{"type": "boolean"},
								"trace-log": 				{"type": "boolean"},
								"gzip-compression": 		{"type": "boolean"},
								"healthcheck-interval":		{"type": "string", "minLength": 2, "pattern": "[0-9]+s|m}"},
								"healthcheck-timeout":		{"type": "string", "minLength": 2, "pattern": "[0-9]+s|m}"},
								"flush-period":				{"type": "string", "minLength": 2, "pattern": "[0-9]+s|m}"},
								"username": 				{"type": "string"},
								"password": 				{"type": "string"},
								"tls-key": 					{"type": "string"},
								"tls-cert": 				{"type": "string"},
								"tls-ca": 					{"type": "string"},
								"tls-insecure-skip-verify": {"type": "boolean"}
							},
							"additionalProperties": false
						},
						"amqp": {
							"type": "object",
							"properties": {
								"enabled":					{"type": "boolean"},
								"url": 						{"type": "string", "format": "uri", "minLength": 1, "maxLength": 255, "pattern": "^(amqps?|amqp?)://"},
								"timeout": 					{"type": "string", "minLength": 2, "pattern": "[0-9]+s|m}"},
								"exchange": 				{"type": "string", "minLength": 1},
								"exchange-type": 			{"type": "string", "enum": ["direct", "topic", "fanout", "header", "x-consistent-hash"]},
								"routing-key": 				{"type": "string", "minLength": 1},
								"delivery-mode": 			{"type": "string", "enum": ["transient", "persistent"]},
								"vhost": 					{"type": "string", "minLength": 1},
								"passive": 					{"type": "boolean"},
								"durable": 					{"type": "boolean"},
								"username": 				{"type": "string"},
								"password": 				{"type": "string"},
								"tls-key": 					{"type": "string"},
								"tls-cert": 				{"type": "string"},
								"tls-ca": 					{"type": "string"},
								"tls-insecure-skip-verify": {"type": "boolean"},
								"headers":					{"type": "object", "additionalProperties": true}
							},
							"additionalProperties": false
						},
						"http": {
							"type": "object",
							"properties": {
								"enabled":					{"type": "boolean"},
								"endpoints": 				{"type": "array", "items": [{"type": "string", "minItems": 1, "format": "uri", "minLength": 1, "maxLength": 255, "pattern": "^(https?|http?)://"}]},
								"timeout": 					{"type": "string", "minLength": 2, "pattern": "[0-9]+s|m}"},
								"method": 					{"type": "string", "enum": ["POST", "PUT"]},
								"serializer": 				{"type": "string", "enum": ["json"]},
								"enable-gzip": 				{"type": "boolean"},
								"proxy-url": 				{"type": "string"},
								"proxy-username": 			{"type": "string"},
								"proxy-password": 			{"type": "string"},
								"username": 				{"type": "string"},
								"password": 				{"type": "string"},
								"tls-key": 					{"type": "string"},
								"tls-cert": 				{"type": "string"},
								"tls-ca": 					{"type": "string"},
								"tls-insecure-skip-verify": {"type": "boolean"},
								"headers":					{"type": "object", "additionalProperties": true}
							},
							"additionalProperties": false
						},
						"eventlog": {
							"type": "object",
							"properties": {
								"enabled":					{"type": "boolean"},
								"level": 					{"type": "string", "enum": ["INFO", "info", "warn", "warning", "WARN", "WARNING", "error", "erro", "ERROR", "ERRO"]},
								"remote-host": 				{"type": "string"},
								"template": 				{"type": "string"}
							},
							"additionalProperties": false
						}
					},
					"additionalProperties": false
				}
			]
		},
		"pe": {
			"type": "object",
			"properties": {
				"enabled":			{"type": "boolean"},
				"read-resources":	{"type": "boolean"},
				"read-symbols":		{"type": "boolean"},
				"read-sections":	{"type": "boolean"},
				"excluded-images":  {"type": "array", "items": [{"type": "string"}]}
			},
			"additionalProperties": false
		},
		"transformers": {
			"type": "object",
			"anyOf": [{
					"properties": {
						"remove": {
							"type": "object",
							"properties": {
								"enabled":  {"type": "boolean"},
								"kparams": 	{"type": "array", "items": [{"type": "string"}]}
							},
							"if": {
								"properties": {"enabled": { "const": true }}
							},
							"then": {
								"properties": {"kparams": 	{"type": "array", "minItems": 1, "items": [{"type": "string"}]}}
							},
							"additionalProperties": false
						},
						"rename": {
							"type": "object",
							"properties": {
								"enabled":  {"type": "boolean"},
								"kparams": 	{"type": "array", "items": [
														{
															"type": "object",
															"properties": {
																"old": {"type": "string", "minLength": 1},
																"new": {"type": "string", "minLength": 1}
															},
															"additionalProperties": false
														}
								]}
							},
							"if": {
								"properties": {"enabled": { "const": true }}
							},
							"then": {
								"properties": {"kparams": {"minItems": 1}}
							},
							"additionalProperties": false
						},
						"replace": {
							"type": "object",
							"properties": {
								"enabled":  		{"type": "boolean"},
								"replacements": 	{"type": "array", "items": [
														{
															"type": "object",
															"properties": {
																"kparam": 	{"type": "string", "minLength": 1},
																"old": 		{"type": "string", "minLength": 1},
																"new": 		{"type": "string"}
															},
															"additionalProperties": false
														}
								]}
							},
							"if": {
								"properties": {"enabled": { "const": true }}
							},
							"then": {
								"properties": {"replacements": 	{"minItems": 1}}
							},
							"additionalProperties": false
						},
						"tags": {
							"type": "object",
							"properties": {
								"enabled":  {"type": "boolean"},
								"tags": 	{"type": "array", "items": [
														{
															"type": "object",
															"properties": {
																"key": 	 {"type": "string", "minLength": 1},
																"value": {"type": "string", "minLength": 1}
															},
															"additionalProperties": false
														}
								]}
							},
							"if": {
								"properties": {"enabled": { "const": true }}
							},
							"then": {
								"properties": {"tags": 	{"minItems": 1}}
							},
							"additionalProperties": false
						},
						"trim": {
							"type": "object",
							"properties": {
								"enabled":  		{"type": "boolean"},
								"prefixes": 		{"type": "array", "items": [
														{
															"type": "object",
															"properties": {
																"kparam": 	{"type": "string", "minLength": 1},
																"trim": 	{"type": "string", "minLength": 1}
															},
															"additionalProperties": false
														}
								]},
								"suffixes": 		{"type": "array", "items": [
														{
															"type": "object",
															"properties": {
																"kparam": 	{"type": "string", "minLength": 1},
																"trim": 	{"type": "string", "minLength": 1}
															},
															"additionalProperties": false
														}
								]}
							},
							"if": {
								"properties": {"enabled": { "const": true }}
							},
							"then": {
								"properties": {"suffixes": 	{"minItems": 1}, "prefixes": {"minItems": 1}}
							},
							"additionalProperties": false
						}
					},
					"additionalProperties": false
				}
			]
		},
		"yara": {
			"type": "object",
			"properties": {
				"enabled":			{"type": "boolean"},
				"rule":				{
					"type": "object",
					"anyOf": [{
						"properties": {
							"paths":  {"type": "array", "items": [
											{
												"type": "object",
												"properties": {
													"path": 		{"type": "string"},
													"namespace": 	{"type": "string"}
												},
												"if": {
													"properties": {"enabled": {"$ref": "#yara", "const": true }}
												},
												"then": {
													"properties": {"path": 	{"minLength": 0}}
												},
												"additionalProperties": false
											}]
                	                     },
							"strings": 	{"type": "array"}
						},
						"additionalProperties": false
					}]
				},
				"alert-via":		{"type": "string", "enum": ["slack", "mail", "systray"]},
				"alert-template":   {
						"type": 		"object",
						"properties": {
							"text":	 	{"type": "string"},
							"title": 	{"type": "string"}
						},
						"additionalProperties": false
				},
				"fastscan":			{"type": "boolean"},
				"skip-files":		{"type": "boolean"},
				"scan-timeout":		{"type": "string", "minLength": 2, "pattern": "[0-9]+s"},
				"excluded-files":	{"type": "array", "items": [{"type": "string", "minLength": 1}]},
				"excluded-procs":	{"type": "array", "items": [{"type": "string", "minLength": 1}]}
			},
			"additionalProperties": false
		}
	},
	"additionalProperties": false
}
`

var rulesSchema = `
{
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "object",
	"properties": {
		"id": 					{"type": "string", "minLength": 36, "pattern": "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"},
		"version": 				{"type": "string", "minLength": 5, "pattern": "^([0-9]+.)([0-9]+.)([0-9]+)$"},
		"name": 				{"type": "string", "minLength": 3},
        "description":  		{"type": "string"},
		"output": 				{"type": "string", "minLength": 5},
		"notes": 				{"type": "string"},
		"severity":  			{"type": "string", "enum": ["low", "medium", "high", "critical"]},
		"min-engine-version":  	{"type": "string", "minLength": 5, "pattern": "^([0-9]+.)([0-9]+.)([0-9]+)$"},
		"enabled":  			{"type": "boolean"},
		"condition": 			{"type": "string", "minLength": 3},
		"labels": 				{
  			"type": "object",
  			"additionalProperties": { "type": "string"}
		},
		"tags":					{"type": "array", "items": [{"type": "string", "minLength": 1}]},
		"references":			{"type": "array", "items": [{"type": "string", "minLength": 1}]},
		"action": 				{
			"type": "array",
			"items": {
				"type": "object",
				"properties": {
					"name": 	{"type": "string", "enum": ["kill"]}
				},
				"required": ["name"],
				"additionalProperties": false
			}
		}
	},
	"required": ["id", "version", "name", "condition", "min-engine-version"],
	"additionalProperties": false
}
`

var macrosSchema = `
{
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "array",
    "items":
    {
        "type": "object",
        "properties": {
            "macro": 		{"type": "string", "minLength": 2, "pattern": "^[A-Za-z0-9_-]+$"},
            "description":  {"type": "string"},
            "expr":  		{"type": "string", "minLength": 5},
            "list":			{"type": "array", "items": [{"type": "string", "minLength": 1}]}
        },
		"required":     ["macro"],
		"oneOf": [
            {"required": ["expr"]},
            {"required": ["list"]}
        ],
        "additionalProperties": false
    },
    "additionalProperties": false
}
`

type schemaConfig struct {
	MaxBuffers    uint32
	MinBuffers    uint32
	MaxBufferSize uint32
}

func interpolateSchema() string {
	tmpl := template.Must(template.New("schema").Parse(schema))

	var b bytes.Buffer
	err := tmpl.Execute(&b, &schemaConfig{
		MaxBuffers:    defaultMaxBuffers,
		MinBuffers:    defaultMinBuffers,
		MaxBufferSize: maxBufferSize,
	})
	if err != nil {
		return ""
	}

	return b.String()
}
