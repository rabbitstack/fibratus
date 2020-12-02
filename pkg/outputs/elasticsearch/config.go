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

import (
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"github.com/spf13/pflag"
	"time"
)

const (
	esEnabled             = "output.elasticsearch.enabled"
	esServers             = "output.elasticsearch.servers"
	esTimeout             = "output.elasticsearch.timeout"
	esFlushPeriod         = "output.elasticsearch.flush-period"
	esHealthcheck         = "output.elasticsearch.healthcheck"
	esBulkWorkers         = "output.elasticsearch.bulk-workers"
	esHealthcheckInterval = "output.elasticsearch.healthcheck-interval"
	esHealthcheckTimeout  = "output.elasticsearch.healthcheck-timeout"
	esUsername            = "output.elasticsearch.username"
	esPassword            = "output.elasticsearch.password"
	esSniff               = "output.elasticsearch.sniff"
	esTraceLog            = "output.elasticsearch.trace-log"
	esIndexName           = "output.elasticsearch.index-name"
	esTemplateName        = "output.elasticsearch.template-name"
	esTemplateConfig      = "output.elasticsearch.template-config"
	esGzipCompression     = "output.elasticsearch.gzip-compression"
)

// Config contains the options for tweaking the output behaviour.
type Config struct {
	outputs.TLSConfig
	// Enabled determines whether ES output is enabled.
	Enabled bool `mapstructure:"enabled"`
	// Servers contains a comma separated list of Elasticsearch instances that comprise the cluster.
	Servers []string `mapstructure:"servers"`
	// Timeout specifies the connection timeout.
	Timeout time.Duration `mapstructure:"timeout"`
	// FlushPeriod specifies when to flush the bulk at the end of the given interval.
	FlushPeriod time.Duration `mapstructure:"flush-period"`
	// BulkWorkers represents the number of workers that commit docs to Elasticserach.
	BulkWorkers int `mapstructure:"bulk-workers"`
	// Healthcheck enables/disables nodes health checking.
	Healthcheck bool `mapstructure:"healthcheck"`
	// HealthCheckInterval specifies the interval for checking if the Elasticsearch nodes are available.
	HealthCheckInterval time.Duration `mapstructure:"healthcheck-interval"`
	// HealthCheckTimeout sets the timeout for periodic health checks.
	HealthCheckTimeout time.Duration `mapstructure:"healthcheck-timeout"`
	// Username is the user name for the basic HTTP authentication.
	Username string `mapstructure:"username"`
	// Password is the password for the basic HTTP authentication.
	Password string `mapstructure:"password"`
	// Sniff enables the discovery of all Elasticsearch nodes in the cluster. This avoids populating the list of available Elasticsearch nodes.
	Sniff bool `mapstructure:"sniff"`
	// TraceLog determines if the Elasticsearch trace log is enabled. Useful for troubleshooting.
	TraceLog bool `mapstructure:"tracelog"`
	// IndexName represents the target index for kernel events. It allows time specifiers to create indices per time frame.
	IndexName string `mapstructure:"index-name"`
	// TemplateName specifies the name of the index template.
	TemplateName string `mapstructure:"template-name"`
	// TemplateConfig contains the full JSON body of the index template.
	TemplateConfig string `mapstructure:"template-config"`
	// GzipCompression specifies if gzip compression is enabled.
	GzipCompression bool `mapstructure:"gzip-compression"`
}

// AddFlags registers persistent flags.
func AddFlags(flags *pflag.FlagSet) {
	flags.Bool(esEnabled, false, "Determines whether ES output is enabled")
	flags.StringSlice(esServers, []string{"http://127.0.0.1:9200"}, "Contains a comma separated list of Elasticsearch instances that comprise the cluster")
	flags.Duration(esTimeout, time.Second*5, "Specifies the output connection timeout")
	flags.Duration(esFlushPeriod, time.Second, "Specifies when to flush the bulk at the end of the given interval")
	flags.Int(esBulkWorkers, 1, "Represents the number of workers that commit docs to Elasticsearch")
	flags.Bool(esHealthcheck, true, "Enables/disables nodes health checking")
	flags.Duration(esHealthcheckInterval, time.Second*10, "Specifies the interval for checking if the Elasticsearch nodes are available")
	flags.Duration(esHealthcheckTimeout, time.Second*5, "Specifies the timeout for periodic health checks")
	flags.String(esUsername, "", "Identifies the user name for the basic HTTP authentication")
	flags.String(esPassword, "", "Specifies the password for the basic HTTP authentication")
	flags.Bool(esSniff, false, "Enables the discovery of all Elasticsearch nodes in the cluster. This avoids populating the list of available Elasticsearch nodes")
	flags.Bool(esTraceLog, false, "Determines if the Elasticsearch trace log is enabled. Useful for troubleshooting")
	flags.String(esTemplateName, "fibratus", "Specifies the name of the index template")
	flags.String(esIndexName, "fibratus", "Represents the target index for kernel events. It allows time specifiers to create indices per time frame")
	flags.String(esTemplateConfig, "", "Contains the full JSON body of the index template")
	flags.Bool(esGzipCompression, false, "Specifies if gzip compression is enabled")
}
