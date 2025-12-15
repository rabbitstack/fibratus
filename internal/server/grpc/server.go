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
	"net"
	"sync"

	rulesapi "github.com/rabbitstack/fibratus/api/protobuf/rules/v1"
	"github.com/rabbitstack/fibratus/internal/server/rulestore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type Server struct {
	grpcServer *grpc.Server
}

func NewServer() *Server {
	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(authUnaryInterceptor("1234")),
	}

	s := grpc.NewServer(opts...)

	rulesapi.RegisterRuleServiceServer(s, &RuleServiceServer{
		streams: make(map[string]*ruleStream),
		store:   rulestore.NewFS(),
	})

	return &Server{grpcServer: s}
}

func (s *Server) Run() error {
	lis, err := net.Listen("tcp", "127.0.0.1:8090")
	if err != nil {
		return err
	}
	return s.grpcServer.Serve(lis)
}

func authUnaryInterceptor(validToken string) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {

		// 1Already authenticated in this call chain?
		if ok, _ := ctx.Value(authKey{}).(bool); ok {
			// Fast path — no revalidation needed
			return handler(ctx, req)
		}

		// Check if we've validated this connection before
		p, ok := peer.FromContext(ctx)
		if ok {
			if v, found := authCache.Load(p.Addr.String()); found && v.(bool) {
				// Cache hit: mark context authenticated and continue
				ctx = context.WithValue(ctx, authKey{}, true)
				return handler(ctx, req)
			}
		}

		// Validate metadata credentials
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing metadata")
		}

		tokens := md.Get("authorization")
		if len(tokens) == 0 || tokens[0] != validToken {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		// Store validation result and mark context
		if ok && p.Addr != nil {
			authCache.Store(p.Addr.String(), true)
		}

		ctx = context.WithValue(ctx, authKey{}, true)
		return handler(ctx, req)
	}
}

type authKey struct{}

var authCache sync.Map // key: peer.Addr.String(), value: bool

func authStreamInterceptor(validToken string) grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		ctx := ss.Context()

		// Fast path: already authenticated in context
		if ok, _ := ctx.Value(authKey{}).(bool); ok {
			return handler(srv, ss)
		}

		// Check if this connection is already validated
		var p *peer.Peer
		if peerInfo, ok := peer.FromContext(ctx); ok {
			p = peerInfo
			if v, found := authCache.Load(p.Addr.String()); found && v.(bool) {
				ctx = context.WithValue(ctx, authKey{}, true)
				// wrap the stream with new context
				wrapped := &wrappedStream{ServerStream: ss, ctx: ctx}
				return handler(srv, wrapped)
			}
		}

		// Validate the metadata
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return status.Error(codes.Unauthenticated, "missing metadata")
		}

		tokens := md.Get("authorization")
		if len(tokens) == 0 || tokens[0] != validToken {
			return status.Error(codes.Unauthenticated, "invalid token")
		}

		// Mark as authenticated for this connection
		if p != nil && p.Addr != nil {
			authCache.Store(p.Addr.String(), true)
		}

		ctx = context.WithValue(ctx, authKey{}, true)
		wrapped := &wrappedStream{ServerStream: ss, ctx: ctx}
		return handler(srv, wrapped)
	}
}

// wrappedStream injects a new context into the stream
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}
