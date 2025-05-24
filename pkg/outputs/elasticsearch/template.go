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

package elasticsearch

type templateInfo struct {
	IndexPattern string
}

const indexTemplate = `
{
	"index_patterns": [ "{{ .IndexPattern }}" ],
	"settings": {
		"index": {
			"refresh_interval": "5s",
			"number_of_shards": 1,
			"number_of_replicas": 1
		}
	},
	"mappings": {
		"properties": {
			"seq": { "type": "long" },
			"pid": { "type": "long" },
			"tid": { "type": "long" },
			"cpu": { "type": "short" },

			"name": { "type": "keyword" },
			"category": { "type": "keyword" },
			"description": { "type": "text" },
			"host": { "type": "keyword" },

			"timestamp": { "type": "date" },

			"params": { 
				"type": "nested",
			    "properties": {
					"dip": { "type": "ip" },
					"sip": { "type": "ip" }
				}
			},
			
			"ps": {
				"type": "nested",
			    "properties": {
					"pid": { "type": "long" },
					"ppid": { "type": "long" },
					"name": { "type": "keyword" },
					"comm": { "type": "text" },
					"exe": { "type": "text" },
					"cwd": { "type": "text" },
					"sid": { "type": "keyword" },
					"sessionid": { "type": "short" },
					"handles": {
						"type": "nested",
						"properties": {
							"name": { "type": "text" },
							"type": { "type": "text" },
							"id": 	{ "type": "long" },
							"object": { "type": "keyword" }
						}
					}
				}
			}
			
		}
	}
}
`
