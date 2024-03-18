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
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"github.com/hashicorp/go-version"
	"github.com/olivere/elastic/v7"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"github.com/rabbitstack/fibratus/pkg/util/tls"
	log "github.com/sirupsen/logrus"
	"net/http"
)

// minElasticVersion is the minimal supported Elasticsearch version
var minElasticVersion, _ = version.NewVersion("5.5")

var (
	// totalBulkedDocs contains the number of total bulked docs
	totalBulkedDocs = expvar.NewInt("elasticsearch.total.bulked.docs")
	// committedDocs counts the number of docs commited to Elasticsearch
	committedDocs = expvar.NewInt("elasticsearch.committed.docs")
	// failedDocs counts the number of docs that failed to commit to Elasticsearch
	failedDocs = expvar.NewInt("elasticsearch.failed.docs")
)

type elasticsearch struct {
	client        *elastic.Client
	bulkProcessor *elastic.BulkProcessor
	config        Config
	index         index
}

type logger struct{}

func (l logger) Printf(format string, v ...interface{}) {
	log.Infof(format, v...)
}

func init() {
	outputs.Register(outputs.Elasticsearch, initElastic)
}

func initElastic(config outputs.Config) (outputs.OutputGroup, error) {
	cfg, ok := config.Output.(Config)
	if !ok {
		return outputs.Fail(outputs.ErrInvalidConfig(outputs.Elasticsearch, config.Output))
	}

	es := &elasticsearch{config: cfg, index: index{config: cfg}}

	return outputs.Success(es), nil
}

func (e *elasticsearch) Connect() error {
	var opts []elastic.ClientOptionFunc
	var client *elastic.Client
	var err error

	// setup a new HTTP client with optional TLS transport
	tlsConfig, err := tls.MakeConfig(e.config.TLSCert, e.config.TLSKey, e.config.TLSCA, e.config.TLSInsecureSkipVerify)
	if err != nil {
		return fmt.Errorf("invalid TLS config: %v", err)
	}
	httpClient := &http.Client{
		Timeout:   e.config.Timeout,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	opts = append(
		opts,
		elastic.SetSniff(e.config.Sniff),
		elastic.SetHttpClient(httpClient),
		elastic.SetURL(e.config.Servers...),
		elastic.SetGzip(e.config.GzipCompression),
		elastic.SetHealthcheck(e.config.Healthcheck),
		elastic.SetHealthcheckTimeout(e.config.HealthCheckTimeout),
		elastic.SetHealthcheckInterval(e.config.HealthCheckInterval),
	)

	if e.config.Username != "" && e.config.Password != "" {
		opts = append(
			opts,
			elastic.SetBasicAuth(e.config.Username, e.config.Password),
		)
	}
	if e.config.TraceLog {
		opts = append(opts, elastic.SetTraceLog(&logger{}))
	}

	client, err = elastic.NewClient(opts...)
	if err != nil {
		return err
	}

	ver, err := client.ElasticsearchVersion(e.config.Servers[0])
	if err != nil {
		return fmt.Errorf("unable to fetch Elasticsearch version: %v", err)
	}

	v, err := version.NewVersion(ver)
	if err != nil {
		return fmt.Errorf("unable to parse Elasticsearch version %s: %v", ver, err)
	}
	if v.LessThan(minElasticVersion) {
		return fmt.Errorf("required at least Elasticsearch %s but found version %s", minElasticVersion.String(), ver)
	}

	e.client = client
	e.index.client = client

	bulkProcessor, err := client.BulkProcessor().
		After(func(executionId int64, requests []elastic.BulkableRequest, response *elastic.BulkResponse, err error) {
			if err != nil {
				log.Errorf("failed to execute bulk: %s", err)
				return
			}

			if response.Errors {
				log.Errorf("failed to insert %d documents", len(response.Failed()))
				for i, fail := range response.Failed() {
					failedDocs.Add(1)
					log.Errorf("failed to insert document %d: %v", i, fail.Error)
				}
				return
			}
			committedDocs.Add(int64(len(requests)))
		}).
		FlushInterval(e.config.FlushPeriod).
		Workers(e.config.BulkWorkers).
		Do(context.Background())
	if err != nil {
		return fmt.Errorf("couldn't create Elasticsearch bulk processor: %v", err)
	}

	err = e.index.putTemplate()
	if err != nil {
		return err
	}

	err = bulkProcessor.Start(context.Background())
	if err != nil {
		return err
	}

	e.bulkProcessor = bulkProcessor

	log.Infof("established connection to Elasticsearch server(s): %v", e.config.Servers)

	return nil
}

func (e *elasticsearch) Publish(batch *kevent.Batch) error {
	for _, kevt := range batch.Events {
		indexName := e.index.getName(kevt)
		// create the bulk index request for each event in the batch.
		// We already have a valid JSON body, so just pass the raw
		// JSON message as request document
		e.bulkProcessor.Add(newBulkIndexRequest(indexName, kevt))
		totalBulkedDocs.Add(1)
	}
	return nil
}

func newBulkIndexRequest(indexName string, kevt *kevent.Kevent) *elastic.BulkIndexRequest {
	kjson := kevt.MarshalJSON()
	return elastic.NewBulkIndexRequest().Index(indexName).Doc(json.RawMessage(kjson))
}

func (e *elasticsearch) Close() error {
	if e.bulkProcessor != nil {
		// commit outstanding requests before shutdown
		if err := e.bulkProcessor.Flush(); err != nil {
			return err
		}
		return e.bulkProcessor.Close()
	}
	return nil
}
