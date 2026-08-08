//go:build linux

/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package bootstrap

import (
	"errors"

	"github.com/rabbitstack/fibratus/pkg/config"
)

var ErrCaptureNotWired = errors.New("linux event capture is not wired yet")

type App struct {
	config *config.Config
	evs    *EventSourceControl
}

type Option func(*opts)

type opts struct{}

func WithSignals() Option {
	return func(*opts) {}
}

func WithDebugPrivilege() Option {
	return func(*opts) {}
}

func NewApp(cfg *config.Config, options ...Option) (*App, error) {
	if err := InitConfigAndLogger(cfg); err != nil {
		return nil, err
	}
	return &App{config: cfg, evs: NewEventSourceControl(cfg)}, nil
}

func (f *App) Run([]string) error {
	if err := f.evs.Open(f.config); err != nil {
		return err
	}
	return ErrCaptureNotWired
}

func (*App) Wait() {}

func (f *App) Shutdown() error {
	return f.evs.Close()
}
