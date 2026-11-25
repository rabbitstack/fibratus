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
	"errors"

	libetw "github.com/rabbitstack/fibratus/internal/etw"
	"github.com/rabbitstack/fibratus/pkg/event"
	"github.com/rabbitstack/fibratus/pkg/pipeline"
	"github.com/rabbitstack/fibratus/pkg/sys/etw"
)

// Trace is a probe's wrapper around the native ETW trace API with
// an extra state and operations for deocding and publishing events
// to the pipeline.
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
	InitFunc   func(*event.Event)
}

type PubOption func(o *PubOpts)

func WithMutateFunc(fn func(*event.Event)) PubOption {
	return func(o *PubOpts) {
		o.MutateFunc = fn
	}
}

func WithInitFunc(fn func(*event.Event)) PubOption {
	return func(o *PubOpts) {
		o.InitFunc = fn
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
	var errs []error

	if err := t.Trace.Flush(); err != nil {
		errs = append(errs, err)
	}
	if err := t.Trace.Close(); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(append(errs, t.Trace.Stop())...)
}

func (t *Trace[T]) SourceID() pipeline.SourceID {
	return t.id
}

func (t *Trace[T]) Publish(rec *etw.EventRecord, options ...PubOption) error {
	var opts PubOpts

	for _, opt := range options {
		opt(&opts)
	}

	evt := t.pipeline.Acquire(t.id)
	if evt == nil {
		return pipeline.ErrClosed
	}

	if opts.InitFunc != nil {
		opts.InitFunc(evt)
	} else if err := evt.Parse(rec, t.decoder); err != nil {
		t.pipeline.Release(t.id, evt)
		return err
	}

	if opts.MutateFunc != nil {
		opts.MutateFunc(evt)
	}

	t.pipeline.Publish(t.id, evt)
	return nil
}
