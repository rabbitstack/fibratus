# Elasticsearch

The Elasticsearch output ships kernel events to the `_bulk` [API endpoint](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html). Events are batched and flushed when the interval specified by `flush-period` elapses.

### Configuration {docsify-ignore}

The Elasticsearch output configuration is located in the `outputs.elasticsearch` section.

#### enabled

Indicates whether the Elasticsearch output is enabled.

**default**: `false`

#### servers

Defines the URL endpoints of the Elasticsearch nodes.

**default**: `http://localhost:9200`

#### timeout

Represents the initial HTTP connection timeout when connecting to the Elasticsearch cluster.

**default**: `5s`

#### flush-period

Specifies when to flush the bulk at the end of the given interval.

**default**: `1s`

#### bulk-workers

Determines the number of workers that commit docs to Elasticsearch. Higher values maximize the throughout at the cost of increased CPU utilization.

**default**: `1`

#### healthcheck

Enables or disables nodes health checking.

**default**: `true`

#### healthcheck-interval

Specifies the interval for checking if the Elasticsearch nodes are available.

**default**: `10s`

#### healthcheck-timeout

Specifies the timeout for periodic node health checks.

**default**: `5s`

#### username

Identifies the user name for the basic HTTP authentication.

#### password

Identifies the password for the basic HTTP authentication.

#### sniff

Enables the discovery of all Elasticsearch nodes in the cluster. This avoids populating the list of available Elasticsearch nodes.

**default**: `false`

#### trace-log

Determines if the Elasticsearch client trace log is enabled. Useful for troubleshooting.

**default**: `false`

#### gzip-compression

Determines if the `gzip` compression is enabled for Elasticsearch documents.

**default**: `false`

#### template-name

Specifies the name of the index template.

**default**: `fibratus`

#### template-config

Contains the full JSON body of the index template. For more information refer to [index templates](https://www.elastic.co/guide/en/elasticsearch/reference/current/index-templates.html).

**default**:

```
{
	"index_patterns": [ "{{ fibratus* }}" ],
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

			"kparams": {
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
					"sessionid": { "type": "short" }
				}
			}
		}
	}
}
```

#### index-name

Represents the target index for kernel events. It allows time specifiers to create indices per time frame. For example, `fibratus-%Y-%m` generates the index name with current year and month. Supported time specifiers are:

- `%Y` current year in `YYYY` format (`2020`)
- `%y` current year in `YY` format (`20`)
- `%m` current month (`01`)
- `%d` current day (`02`)
- `%H` current hour (`15`)

**default**: `fibratus`

#### tls-key

Path to the public/private key file.

#### tls-cert

Path to the certificate file.

#### tls-ca

Represents the path of the certificate file that is associated with the Certification Authority (CA).

#### tls-insecure-skip-verify

Indicates if the chain and host verification stage is skipped.

**default**: `false`
