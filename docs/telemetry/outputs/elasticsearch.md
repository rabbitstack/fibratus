# Elasticsearch

##### The Elasticsearch output ships events to the Elasticsearch `_bulk` [API endpoint](https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html). Events are collected into batches and flushed at intervals defined by the `flush-period` config option, ensuring efficient indexing while minimizing request overhead.

## Configuration 

The Elasticsearch output configuration is located in the `outputs.elasticsearch` section.

### `enabled`

Indicates whether the Elasticsearch output is enabled.

### `servers`

Defines the URL endpoints of the Elasticsearch nodes.

### `timeout`

Represents the initial HTTP connection timeout when connecting to the Elasticsearch cluster.

### `flush-period`

Specifies when to flush the bulk at the end of the given interval.

### `bulk-workers`

Determines the number of workers that commit docs to Elasticsearch. Higher values maximize the throughout at the cost of increased CPU utilization.

### `healthcheck`

Enables or disables nodes health checking.

### `healthcheck-interval`

Specifies the interval for checking if the Elasticsearch nodes are available.

### `healthcheck-timeout`

Specifies the timeout for periodic node health checks.

### `username`

Identifies the user name for the basic HTTP authentication.

### `password`

Identifies the password for the basic HTTP authentication.

### `sniff`

Enables the discovery of all Elasticsearch nodes in the cluster. This avoids populating the list of available Elasticsearch nodes.

### `trace-log`

Determines if the Elasticsearch client trace log is enabled. Useful for troubleshooting.

### `gzip-compression`

Determines if the `gzip` compression is enabled for Elasticsearch documents.

### `template-name`

Specifies the name of the index template.

### `template-config`

Contains the full JSON body of the index template. For more information refer to [index templates](https://www.elastic.co/guide/en/elasticsearch/reference/current/index-templates.html).

### `index-name`

Represents the target index for the telemetry. It allows time specifiers to create indices per time frame. For example, `fibratus-%Y-%m` generates the index name with current year and month. Supported time specifiers are:

- `%Y` current year in `YYYY` format (`2020`)
- `%y` current year in `YY` format (`20`)
- `%m` current month (`01`)
- `%d` current day (`02`)
- `%H` current hour (`15`)

### `tls-key`

Path to the public/private key file.

### `tls-cert`

Path to the certificate file.

### `tls-ca`

Represents the path of the certificate file that is associated with the Certification Authority (CA).

### `tls-insecure-skip-verify`

Indicates if the chain and host verification stage is skipped.
