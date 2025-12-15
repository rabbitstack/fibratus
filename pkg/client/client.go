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
	"fmt"
	"net"
	"time"

	rulesapi "github.com/rabbitstack/fibratus/api/protobuf/rules/v1"
	"github.com/rabbitstack/fibratus/pkg/ruleset"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	// DefaultMaxRecvMsgSize defines the default maximum message size for
	// receiving protobufs passed over the GRPC API.
	DefaultMaxRecvMsgSize = 16 << 20
	// DefaultMaxSendMsgSize defines the default maximum message size for
	// sending protobufs passed over the GRPC API.
	DefaultMaxSendMsgSize = 16 << 20
)

type Client interface {
	ListRules(context.Context, *RuleListOptions) (*ruleset.RuleSet, error)
	WatchRules(context.Context) (<-chan *ruleset.RuleSet, <-chan error)
}

type client struct {
	conn *grpc.ClientConn

	ruleStore *RuleStore
}

// New the call to the constructor returns immediately
// and the connection to the server is performed in the
// background.
func New() (Client, error) {
	backoffConfig := backoff.DefaultConfig
	backoffConfig.MaxDelay = time.Second * 20
	connParams := grpc.ConnectParams{
		Backoff:           backoffConfig,
		MinConnectTimeout: time.Second * 20,
	}

	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithConnectParams(connParams),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{}
			c, err := d.DialContext(ctx, "tcp", addr)
			if err != nil {
				return nil, err
			}
			return c, nil
		}),
	}

	opts = append(opts, grpc.WithDefaultCallOptions(
		grpc.MaxCallRecvMsgSize(DefaultMaxRecvMsgSize),
		grpc.MaxCallSendMsgSize(DefaultMaxSendMsgSize)))

	md := map[string]string{"authorization": "1234"}
	opts = append(opts, grpc.WithUnaryInterceptor(metadataUnaryInterceptor(md)))

	connector := func() (*grpc.ClientConn, error) {
		conn, err := grpc.NewClient("localhost:8090", opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %q: %w", "localhost:8090", err)
		}
		return conn, nil
	}
	conn, err := connector()
	if err != nil {
		return nil, err
	}

	c := &client{
		conn:      conn,
		ruleStore: &RuleStore{client: rulesapi.NewRuleServiceClient(conn)},
	}

	return c, nil
}

func (c *client) ListRules(ctx context.Context, opts *RuleListOptions) (*ruleset.RuleSet, error) {
	return c.ruleStore.List(ctx, opts)
}

func (c *client) WatchRules(ctx context.Context) (<-chan *ruleset.RuleSet, <-chan error) {
	return c.ruleStore.Stream(ctx)
}

func metadataUnaryInterceptor(meta map[string]string) grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		md := metadata.New(meta)
		ctx = metadata.NewOutgoingContext(ctx, md)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}
