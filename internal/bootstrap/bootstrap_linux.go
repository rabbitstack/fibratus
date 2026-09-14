//go:build linux

/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
 * Copyright 2026 by Mostafa Moradian
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
	"fmt"
	"os"
	"syscall"

	"github.com/rabbitstack/fibratus/pkg/aggregator"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/api"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/rules"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/rabbitstack/fibratus/pkg/util/signals"
	"github.com/rabbitstack/fibratus/pkg/util/version"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const instanceLockPath = "/tmp/fibratus.lock"

// ErrAlreadyRunning signals a Fibratus process is already running.
var ErrAlreadyRunning = errors.New("an instance of Fibratus process is already running in the system")

// App centralizes the core building blocks responsible
// for event acquisition, rule engine initialization,
// and event routing to the output sinks.
type App struct {
	config  *config.Config
	evs     *EventSourceControl
	engine  *rules.Engine
	psnap   ps.Snapshotter
	agg     *aggregator.BufferedAggregator
	signals chan struct{}
	lock    *os.File
}

// Option enables changing the behaviour of the bootstrap application.
type Option func(*opts)

type opts struct {
	installSignals bool
}

// WithSignals installs signal handlers.
func WithSignals() Option {
	return func(o *opts) {
		o.installSignals = true
	}
}

// WithDebugPrivilege is a no-op on Linux.
func WithDebugPrivilege() Option {
	return func(*opts) {}
}

// NewApp constructs a new bootstrap application with the specified configuration
// and a list of options.
func NewApp(cfg *config.Config, options ...Option) (*App, error) {
	if err := InitConfigAndLogger(cfg); err != nil {
		return nil, err
	}
	var o opts
	var sigs chan struct{}
	for _, opt := range options {
		opt(&o)
	}
	if o.installSignals {
		sigs = signals.Install()
	}

	psnap := ps.NewSnapshotter()

	var engine *rules.Engine
	var rs *config.RulesCompileResult
	if cfg.Filters != nil && cfg.Filters.Rules.Enabled && !cfg.ForwardMode && !cfg.IsCaptureSet() && !cfg.IsFilamentSet() {
		engine = rules.NewEngine(psnap, cfg)
		var err error
		rs, err = engine.Compile()
		if err != nil {
			return nil, err
		}
		if rs != nil {
			log.Infof("rules compile summary: %s", rs)
		}
	} else {
		log.Info("rule engine is disabled")
	}

	return &App{
		config:  cfg,
		evs:     NewEventSourceControl(psnap, cfg, rs),
		engine:  engine,
		psnap:   psnap,
		signals: sigs,
	}, nil
}

// Run configures and opens the event source to start consuming events.
func (f *App) Run(args []string) error {
	if f.evs == nil {
		panic("event source is nil")
	}
	cfg := f.config

	if cfg.IsFilamentSet() {
		return fmt.Errorf("filaments are not supported on Linux")
	}

	lock, err := acquireInstanceLock()
	if err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return ErrAlreadyRunning
		}
		return fmt.Errorf("acquiring instance lock: %w", err)
	}
	f.lock = lock

	log.Infof("bootstrapping with pid %d. Version: %s", os.Getpid(), version.Get())
	log.Infof("configuration options: %s", cfg.Print())

	fltr, err := filter.NewFromCLI(args, cfg)
	if err != nil {
		return err
	}
	if fltr != nil {
		f.evs.SetFilter(fltr)
	}
	if f.engine != nil {
		f.evs.RegisterEventListener(f.engine)
	}

	if err := f.evs.Open(cfg); err != nil {
		return multierror.Wrap(err, f.evs.Close())
	}

	f.agg, err = aggregator.NewBuffered(
		f.evs.Events(),
		f.evs.Errors(),
		cfg.Aggregator,
		cfg.Output,
		cfg.Transformers,
		cfg.Alertsenders,
	)
	if err != nil {
		return err
	}
	return api.StartServer(cfg)
}

// Wait waits for the app to receive the termination signal.
func (f *App) Wait() {
	if f.signals != nil {
		<-f.signals
	}
}

// Shutdown is responsible for tearing down everything gracefully.
func (f *App) Shutdown() error {
	errs := make([]error, 0)
	if f.evs != nil {
		if err := f.evs.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if f.psnap != nil {
		if err := f.psnap.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if f.agg != nil {
		if err := f.agg.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := api.CloseServer(); err != nil {
		errs = append(errs, err)
	}
	if err := alertsender.ShutdownAll(); err != nil {
		errs = append(errs, err)
	}
	if f.lock != nil {
		_ = unix.Flock(int(f.lock.Fd()), unix.LOCK_UN)
		_ = f.lock.Close()
		_ = os.Remove(instanceLockPath)
	}
	return multierror.Wrap(errs...)
}

func acquireInstanceLock() (*os.File, error) {
	f, err := os.OpenFile(instanceLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}
