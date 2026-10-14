/*
 * Copyright 2019-2026 by Nedim Sabic Sabic
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

package probe

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/rabbitstack/fibratus/pkg/event"
)

const (
	defaultConsumerChanSize = 50
)

// EventConsumer defines a probe event consumer
type EventConsumer struct {
	consumer     EventConsumerHandler
	eventCh      chan *event.Event
	eventDropped atomic.Int64
}

// Start the consumer
func (p *EventConsumer) Start(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case event := <-p.eventCh:
				p.consumer.HandleEvent(event)
			}
		}
	}()
}

type PlatformProbe struct {
	consumers      []*EventConsumer
	eventHandlers  []EventHandler                       // listen all events
	eventConsumers [event.MaxEvent + 1][]*EventConsumer // listen all or specific events
}

// AddEventConsumer sets a probe event consumer
func (p *PlatformProbe) AddEventConsumer(consumer EventConsumerHandler) error {
	chanSize := consumer.ChanSize()
	if chanSize <= 0 {
		chanSize = defaultConsumerChanSize
	}

	pc := &EventConsumer{
		consumer: consumer,
		eventCh:  make(chan *event.Event, chanSize),
	}

	for _, eventType := range consumer.EventTypes() {
		if eventType >= event.MaxEvent {
			return fmt.Errorf("event type (%s) not allowed", eventType)
		}

		if eventType.OnlyState() {
			continue
		}

		p.eventConsumers[eventType] = append(p.eventConsumers[eventType], pc)
	}

	p.consumers = append(p.consumers, pc)

	return nil
}

// AddEventHandler sets a probe event handler for the UnknownEventType which requires access to all the struct fields
func (p *PlatformProbe) AddEventHandler(handler EventHandler) error {
	p.eventHandlers = append(p.eventHandlers, handler)

	return nil
}

func (p *PlatformProbe) sendEventToHandlers(event *event.Event) error {
	for _, handler := range p.eventHandlers {
		if err := handler.HandleEvent(event); err != nil {
			return err
		}
	}

	return nil
}

func (p *PlatformProbe) sendEventToConsumers(event *event.Event) error {
	if t := event.Type; int(t) >= len(p.eventConsumers) {
		return fmt.Errorf("invalid event for consumer routing: %s", t)
	}

	for _, pc := range p.eventConsumers[event.Type] {
		select {
		case pc.eventCh <- event.Clone():
		default:
			pc.eventDropped.Add(1)
		}
	}

	return nil
}
