/*
 * Copyright 2019-present by Nedim Sabic Sabic
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

package grpc

import (
	"context"
	"sync"

	rulesapi "github.com/rabbitstack/fibratus/api/protobuf/rules/v1"
	"github.com/rabbitstack/fibratus/internal/server/rulestore"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type RuleServiceServer struct {
	rulesapi.UnimplementedRuleServiceServer
	streams map[string]*ruleStream
	mu      sync.RWMutex
	store   rulestore.Store
	errsc   chan error
}

type ruleStream struct {
	id     string
	stream grpc.ServerStreamingServer[rulesapi.StreamResponse]
	msgsc  chan *rulesapi.StreamResponse
	ctx    context.Context
	cancel context.CancelFunc
}

func (r *RuleServiceServer) List(ctx context.Context, req *rulesapi.ListRequest) (*rulesapi.ListResponse, error) {
	rs, err := r.store.List()
	if err != nil {
		return nil, err
	}
	return &rulesapi.ListResponse{Ruleset: rs}, nil
}

func (r *RuleServiceServer) Stream(req *rulesapi.StreamRequest, stream grpc.ServerStreamingServer[rulesapi.StreamResponse]) error {
	log.Info("new endpoint connected for rule streaming")

	r.addStream("1", stream)

	<-stream.Context().Done() // Block until client disconnects
	r.removeStream("1")

	log.Info("endpoint disconnected from rule streaming")

	return nil
}

func (r *RuleServiceServer) addStream(id string, stream grpc.ServerStreamingServer[rulesapi.StreamResponse]) {
	ctx, cancel := context.WithCancel(stream.Context())
	s := &ruleStream{
		id:     id,
		stream: stream,
		msgsc:  make(chan *rulesapi.StreamResponse, 100),
		ctx:    ctx,
		cancel: cancel,
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.streams[id] = s

	go r.handleStream(s)
}

func (r *RuleServiceServer) removeStream(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.streams[id]; ok {
		c.cancel()
		close(c.msgsc)
		delete(r.streams, id)
	}
}

func (r *RuleServiceServer) handleStream(s *ruleStream) {
	for {
		select {
		case msg := <-s.msgsc:
			if err := s.stream.Send(msg); err != nil {
				r.removeStream(s.id)
				return
			}
		case <-s.ctx.Done():
			r.removeStream(s.id)
			return
		}
	}
}

func (r *RuleServiceServer) broadcast(msg *rulesapi.StreamResponse) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, c := range r.streams {
		select {
		case c.msgsc <- msg:
			log.Info("sending ruleset message")
			// sent successfully
		default:
			// buffer full → drop message
		}
	}
}
