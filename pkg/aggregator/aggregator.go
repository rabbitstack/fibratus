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
	"errors"
	"expvar"
	"time"

	"github.com/rabbitstack/fibratus/pkg/aggregator/transformers"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs"
	log "github.com/sirupsen/logrus"

	// initialize outputs
	_ "github.com/rabbitstack/fibratus/pkg/outputs/amqp"
	_ "github.com/rabbitstack/fibratus/pkg/outputs/console"
	_ "github.com/rabbitstack/fibratus/pkg/outputs/elasticsearch"
	_ "github.com/rabbitstack/fibratus/pkg/outputs/eventlog"
	_ "github.com/rabbitstack/fibratus/pkg/outputs/http"
	_ "github.com/rabbitstack/fibratus/pkg/outputs/null"

	// initialize alert senders
	_ "github.com/rabbitstack/fibratus/pkg/alertsender/mail"
	_ "github.com/rabbitstack/fibratus/pkg/alertsender/slack"

	// initialize transformers
	_ "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/remove"
	_ "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/rename"
	_ "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/replace"
	_ "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/tags"
	_ "github.com/rabbitstack/fibratus/pkg/aggregator/transformers/trim"
)

var (
	// keventsDequeued counts the number of dequeued events
	keventsDequeued = expvar.NewInt("kstream.kevents.dequeued")
	// flushesCount computes the total count of aggregator flushes
	flushesCount = expvar.NewInt("aggregator.flushes.count")
	// batchEvents represents the overall number of processed batches
	batchEvents = expvar.NewInt("aggregator.batch.events")
	// transformerErrors is the count of errors occurred when applying transformers
	transformerErrors = expvar.NewMap("aggregator.transformer.errors")
	// keventErrors is the number of event errors
	keventErrors = expvar.NewInt("aggregator.kevent.errors")
)

// BacklogQueueSize the max size of the backlog queue
const BacklogQueueSize = 800

// BufferedAggregator collects events from the inbound channel and produces batches on regular intervals. The batches
// are pushed to the work queue from which load-balanced configured workers consume the batches and publish to the outputs.
type BufferedAggregator struct {
	kevtsc  chan *kevent.Kevent
	errsc   chan error
	stop    chan struct{}
	flusher *time.Ticker
	// queue of inbound kernel events
	kevts []*kevent.Kevent
	// work queue that forwarder passes to outputs
	wq         queue
	submitter  *submitter
	transforms []transformers.Transformer
	c          Config
	listeners  []Listener

	// stores delayed events
	backlog *backlog
}

// NewBuffered creates a new instance of the event aggregator.
func NewBuffered(
	evts chan *kevent.Kevent,
	errs chan error,
	aggConfig Config,
	outputConfig outputs.Config,
	transformerConfigs []transformers.Config,
	alertsenderConfigs []alertsender.Config,
) (*BufferedAggregator, error) {
	flushInterval := aggConfig.FlushPeriod
	if flushInterval < time.Millisecond*250 {
		flushInterval = time.Millisecond * 250
	}
	agg := &BufferedAggregator{
		kevtsc:    evts,
		kevts:     make([]*kevent.Kevent, 0),
		errsc:     errs,
		stop:      make(chan struct{}, 1),
		flusher:   time.NewTicker(flushInterval),
		wq:        make(chan *kevent.Batch),
		c:         aggConfig,
		listeners: make([]Listener, 0),
		backlog:   newBacklog(BacklogQueueSize),
	}

	var err error
	agg.submitter, err = newSubmitter(agg.wq, outputConfig)
	if err != nil {
		return nil, err
	}
	agg.transforms, err = transformers.LoadAll(transformerConfigs)
	if err != nil {
		return nil, err
	}

	err = alertsender.LoadAll(alertsenderConfigs)
	if err != nil {
		return nil, err
	}

	return agg, nil
}

// Stop flushes pending event batches and instructs the aggregator to stop processing events.
func (agg *BufferedAggregator) Stop() error {
	agg.stop <- struct{}{}

	// flush enqueued events
	b := kevent.NewBatch(agg.kevts...)
	if b.Len() > 0 {
		done := make(chan struct{}, 1)
		go func() {
			agg.wq <- b
			done <- struct{}{}
		}()

		select {
		case <-done:
			close(agg.wq)
		case <-time.After(agg.c.FlushTimeout):
			return errors.New("fail to flush events after stop timed out")
		}
	}

	// sleep a bit before closing the clients
	time.Sleep(time.Millisecond * 150)

	err := agg.submitter.shutdown()
	if err != nil {
		return err
	}

	return nil
}

// Run runs the aggregator main loop.
func (agg *BufferedAggregator) Run() {
	go agg.run()
}

// AddListener registers a new aggregator listener. The listener is
// called for each event coming out of the event queue, before the
// batch is created. If any of the listeners returns a false value,
// the event is rejected.
func (agg *BufferedAggregator) AddListener(lis Listener) {
	agg.listeners = append(agg.listeners, lis)
}

// run starts the aggregator loop. The aggregator receives event stream from the upstream channel, buffers
// them to intermediate queue and dispatches batches to downstream worker queue.
func (agg *BufferedAggregator) run() {
	for {
		select {
		case <-agg.stop:
			agg.flusher.Stop()
			return
		case <-agg.flusher.C:
			if len(agg.kevts) == 0 {
				continue
			}
			b := kevent.NewBatch(agg.kevts...)
			l := b.Len()
			batchEvents.Add(l)
			// push the batch to the work queue
			if l > 0 {
				agg.wq <- b
			}
			flushesCount.Add(1)
			// clear the queue
			agg.kevts = nil
		case evt := <-agg.kevtsc:
			// put delayed event in backlog
			if evt.Delayed {
				agg.backlog.put(evt)
				continue
			}
			// lookup backlog for delayed event
			ev := agg.backlog.pop(evt)
			if ev != nil {
				ev.CopyFields(evt)
				if !agg.push(ev) {
					goto push
				}
			}
		push:
			if !agg.push(evt) {
				continue
			}
		case err := <-agg.errsc:
			keventErrors.Add(1)
			log.Errorf("event processing failure: %v", err)
		}
	}
}

func (agg *BufferedAggregator) push(evt *kevent.Kevent) bool {
	for _, lis := range agg.listeners {
		if !lis.ProcessEvent(evt) {
			evt.Release()
			return false
		}
	}
	for _, tra := range agg.transforms {
		err := tra.Transform(evt)
		if err != nil {
			transformerErrors.Add(err.Error(), 1)
		}
	}
	// push the event to the queue
	agg.kevts = append(agg.kevts, evt)
	keventsDequeued.Add(1)
	return true
}
