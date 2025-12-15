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

package client

import (
	"context"
	"errors"
	"time"

	rulesapi "github.com/rabbitstack/fibratus/api/protobuf/rules/v1"
	"github.com/rabbitstack/fibratus/pkg/ruleset"
	log "github.com/sirupsen/logrus"
)

// RuleListOptions defines the options used to obtain the ruleset.
type RuleListOptions struct {
	WithBackoff bool
	ListYara    bool
	MaxBackoff  time.Duration
}

type RuleStore struct {
	client rulesapi.RuleServiceClient
}

func (r *RuleStore) List(ctx context.Context, opts *RuleListOptions) (*ruleset.RuleSet, error) {
	req := &rulesapi.ListRequest{
		ListYara: opts.ListYara,
	}
	resp, err := r.client.List(ctx, req)
	if err != nil && !opts.WithBackoff {
		return nil, err
	}

	if err != nil {
		maxBackoff := opts.MaxBackoff
		if maxBackoff == 0 {
			maxBackoff = time.Minute * 15
		}
		b := newExpBackOff(maxBackoff)

		err = b.retry(func() error {
			select {
			case <-ctx.Done():
				if errors.Is(ctx.Err(), context.Canceled) {
					// stop retrying
					return nil
				}
			default:
			}
			resp, err = r.client.List(ctx, req)
			if err != nil {
				log.Warnf("unable to fetch rules from the server: %s. Retrying in %v...", err, b.nextBackOff())
			}
			return err
		})

		if err != nil {
			return nil, err
		}
		if resp == nil && err == nil {
			return nil, context.Canceled
		}
		return fromRuleSetProto(resp.Ruleset), nil
	}

	return fromRuleSetProto(resp.Ruleset), nil
}

func (r *RuleStore) Stream(ctx context.Context) (ch <-chan *ruleset.RuleSet, errs <-chan error) {
	var (
		evq  = make(chan *ruleset.RuleSet)
		errq = make(chan error, 1)
	)

	errs = errq
	ch = evq

	stream, err := r.client.Stream(ctx, &rulesapi.StreamRequest{})
	if err != nil {
		errq <- err
		close(errq)
		return
	}

	go func() {
		defer close(errq)

		for {
			rs, err := stream.Recv()
			if err != nil {
				errq <- err
				return
			}

			select {
			case evq <- fromRuleSetProto(rs.Ruleset):
			case <-ctx.Done():
				if cerr := ctx.Err(); cerr != context.Canceled {
					errq <- cerr
				}
				return
			}
		}
	}()

	return ch, errs
}

func fromRuleSetProto(pb *rulesapi.RuleSet) *ruleset.RuleSet {
	rs := &ruleset.RuleSet{}
	rs.FromProto(pb)
	return rs
}
