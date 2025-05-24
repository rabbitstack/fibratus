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

package aggregator

import (
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type httpClient struct {
	url               string
	published         int
	expectedPublished int
	wait              chan struct{}
}

func (c *httpClient) Connect() error {
	//nolint:noctx
	res, err := http.Get(c.url + "/connect")
	if err != nil {
		return err
	}
	defer func() {
		_ = res.Body.Close()
	}()
	if res.StatusCode != http.StatusOK {
		return err
	}
	return nil
}

func (c *httpClient) Close() error { return nil }

func (c *httpClient) Publish(b *event.Batch) error {
	//nolint:noctx
	res, err := http.Post(c.url+"/publish", "application/json", nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = res.Body.Close()
	}()
	c.published++
	if c.published == c.expectedPublished {
		c.wait <- struct{}{}
	}
	return nil
}

func TestRunWorker(t *testing.T) {
	q := make(chan *event.Batch, 2)
	q <- &event.Batch{}
	q <- &event.Batch{}

	mux := http.NewServeMux()
	mux.HandleFunc("/publish", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &httpClient{url: srv.URL, wait: make(chan struct{}, 1), expectedPublished: 2}

	w := initWorker(q, client)
	defer w.close()

	<-client.wait

	assert.Equal(t, 2, client.published)
}

func TestConnectClientBackoff(t *testing.T) {
	q := make(chan *event.Batch, 2)
	q <- &event.Batch{}
	q <- &event.Batch{}

	fail := true

	mux := http.NewServeMux()
	mux.HandleFunc("/publish", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &httpClient{url: srv.URL, wait: make(chan struct{}, 1), expectedPublished: 2}

	go time.AfterFunc(time.Second*3, func() {
		fail = false
	})

	w := initWorker(q, client)
	defer w.close()

	<-client.wait

	assert.Equal(t, 2, client.published)
}
