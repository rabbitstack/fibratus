//go:build windows

/*
 * Copyright 2026 by Nedim Sabic Sabic
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
	"time"

	libetw "github.com/rabbitstack/fibratus/internal/etw"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/pipeline"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
)

// Trace is a probe wrapper around the native ETW trace API with
// an extra state and operations to publish events to the pipeline.
type Trace[T libetw.Trace] struct {
	Trace T

	decoder  *event.ParamDecoder
	pipeline *pipeline.Pipeline

	id pipeline.SourceID
}

type TracePublisher interface {
	Publish(rec *etw.EventRecord, opts ...PubOption) error
}

type PubOpts struct {
	MutateFunc func(*event.Event)
}

type PubOption func(o *PubOpts)

func WithMutateFunc(fn func(*event.Event)) PubOption {
	return func(o *PubOpts) {
		o.MutateFunc = fn
	}
}

func newTrace[T libetw.Trace](t T, id pipeline.SourceID, pipeline *pipeline.Pipeline) *Trace[T] {
	return &Trace[T]{Trace: t, id: id, pipeline: pipeline, decoder: &event.ParamDecoder{}}
}

func (t *Trace[T]) Run() error {
	if err := t.Trace.Start(); err != nil {
		return err
	}

	if err := t.Trace.Open(); err != nil {
		return err
	}

	return t.Trace.CaptureState()
}

func (t *Trace[T]) Shutdown() error {
	var errs multierror.MultiError

	if err := t.Trace.Flush(); err != nil {
		errs.Add(err)
	}

	time.Sleep(time.Millisecond * 100)

	if err := t.Trace.Close(); err != nil {
		errs.Add(err)
	}

	return errs.Wrap(t.Trace.Stop())
}

func (t *Trace[T]) SourceID() pipeline.SourceID {
	return t.id
}

func (t *Trace[T]) Publish(rec *etw.EventRecord, opts ...PubOption) error {
	var options PubOpts

	for _, opt := range opts {
		opt(&options)
	}

	ev := t.pipeline.Acquire(t.id)
	if ev == nil {
		return pipeline.ErrClosed
	}

	if err := ev.Parse(rec, t.decoder); err != nil {
		t.pipeline.Release(t.id, ev)
		return err
	}

	if options.MutateFunc != nil {
		options.MutateFunc(ev)
	}

	t.pipeline.Publish(t.id, ev)

	return nil
}
