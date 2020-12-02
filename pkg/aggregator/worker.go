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
	"expvar"
	"github.com/rabbitstack/fibratus/pkg/outputs"
	log "github.com/sirupsen/logrus"
	"time"
)

// maxBackoff determines the maximum exponential backoff wait time before reconnecting the client
const maxBackoff = time.Minute

var clientPublishErrors = expvar.NewInt("aggregator.worker.client.publish.errors")

type worker struct {
	qu      queue
	client  outputs.Client
	backoff time.Duration
}

func initWorker(q queue, client outputs.Client) *worker {
	w := &worker{qu: q, client: client, backoff: time.Second * 2}
	go w.run()
	return w
}

func (w *worker) run() {
	for {
		err := w.client.Connect()
		if err != nil {
			// schedule an exponential backoff reconnect strategy for the client
			w.backoff *= 2
			log.Warnf("fail to connect the client: %v. Reconnecting in %v...", err, w.backoff)
			if w.backoff > maxBackoff {
				w.backoff = maxBackoff
			}
			<-time.After(w.backoff)
			continue
		}
		break
	}
	for batch := range w.qu {
		if err := w.client.Publish(batch); err != nil {
			clientPublishErrors.Add(1)
			log.Warnf("couldn't publish batch to client: %v", err)
		}
	}
}

func (w *worker) close() error {
	return w.client.Close()
}
