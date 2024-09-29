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
	"context"
	"errors"
	"github.com/rabbitstack/fibratus/pkg/aggregator"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/api"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filament"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kcap"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/symbolize"
	"github.com/rabbitstack/fibratus/pkg/sys"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/rabbitstack/fibratus/pkg/util/signals"
	"github.com/rabbitstack/fibratus/pkg/util/version"
	"github.com/rabbitstack/fibratus/pkg/yara"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"os"
)

// ErrAlreadyRunning signals a Fibratus process is already running in the system
var ErrAlreadyRunning = errors.New("an instance of Fibratus process is already running in the system")

// App centralizes the core building blocks responsible
// for event acquisition, rule engine initialization,
// captures handling, filament execution and event routing
// to the output sinks.
type App struct {
	config     *config.Config
	evs        *EventSourceControl
	symbolizer *symbolize.Symbolizer
	rules      *filter.Rules
	hsnap      handle.Snapshotter
	psnap      ps.Snapshotter
	filament   filament.Filament
	agg        *aggregator.BufferedAggregator
	writer     kcap.Writer
	reader     kcap.Reader
	signals    chan struct{}
}

// Option enables changing the behaviour of the bootstrap application.
type Option func(*opts)

type opts struct {
	setDebugPrivilege bool
	installSignals    bool
	isCaptureReplay   bool
	handleSnapshotFn  handle.SnapshotBuildCompleted
}

// WithSignals installs signal handlers.
func WithSignals() Option {
	return func(o *opts) {
		o.installSignals = true
	}
}

// WithDebugPrivilege injects the SeDebugPrivilege in the process access token.
func WithDebugPrivilege() Option {
	return func(o *opts) {
		o.setDebugPrivilege = true
	}
}

// WithCaptureReplay denotes the capture file is being replayed.
func WithCaptureReplay() Option {
	return func(o *opts) {
		o.isCaptureReplay = true
	}
}

// WithHandleSnapshotFn sets the handle snapshotter completion function.
func WithHandleSnapshotFn(fn handle.SnapshotBuildCompleted) Option {
	return func(o *opts) {
		o.handleSnapshotFn = fn
	}
}

// NewApp constructs a new bootstrap application with the specified configuration
// and a list of options. The configuration is passed from individual command work
// functions.
func NewApp(cfg *config.Config, options ...Option) (*App, error) {
	if err := InitConfigAndLogger(cfg); err != nil {
		return nil, err
	}
	var opts opts
	var sigs chan struct{}
	for _, opt := range options {
		opt(&opts)
	}
	if cfg.DebugPrivilege && opts.setDebugPrivilege {
		sys.SetDebugPrivilege()
	}
	if opts.installSignals {
		sigs = signals.Install()
	}
	if opts.isCaptureReplay {
		reader, err := kcap.NewReader(cfg.KcapFile, cfg)
		if err != nil {
			return nil, err
		}
		app := &App{
			config:  cfg,
			reader:  reader,
			signals: sigs,
		}
		return app, nil
	}

	hsnap := handle.NewSnapshotter(cfg, opts.handleSnapshotFn)
	psnap := ps.NewSnapshotter(hsnap, cfg)

	var (
		rules *filter.Rules
		res   *config.RulesCompileResult
	)
	if cfg.Filters.Rules.Enabled && !cfg.ForwardMode && !cfg.IsCaptureSet() {
		rules = filter.NewRules(psnap, cfg)
		var err error
		res, err = rules.Compile()
		if err != nil {
			return nil, err
		}
		if res != nil {
			log.Infof("rules compile summary: %s", res)
		}
	} else {
		log.Info("rule engine is disabled")
	}

	evs := NewEventSourceControl(psnap, hsnap, cfg, res)

	app := &App{
		config:  cfg,
		evs:     evs,
		rules:   rules,
		hsnap:   hsnap,
		psnap:   psnap,
		signals: sigs,
	}
	return app, nil
}

// Run configure and opens the event source to start consuming events.
// Depending on whether the filament is provided, this method will either
// spin up a filament or set up the aggregator to start forwarding events
// to the rule engine and output sinks.
func (f *App) Run(args []string) error {
	if f.evs == nil {
		panic("event source is nil")
	}
	cfg := f.config

	if !f.isSingleInstance() {
		return ErrAlreadyRunning
	}

	log.Infof("bootstrapping with pid %d. Version: %s", os.Getpid(), version.Get())
	log.Infof("configuration dump %s", cfg.Print())

	// build the filter from the CLI argument. If we got
	// a valid expression the filter is attached to the
	// event consumer
	kfilter, err := filter.NewFromCLI(args, cfg)
	if err != nil {
		return err
	}
	if kfilter != nil {
		f.evs.SetFilter(kfilter)
	}
	// user can either instruct to bootstrap a filament or
	// start a regular run. We'll set up the corresponding
	// components accordingly to what we got from the CLI options.
	// If a filament was given, we'll assign it the previous filter
	// if it wasn't provided in the filament init function.
	// Finally, we open the event source and run the filament i.e.
	// Python main thread in a new goroutine.
	// In case of a regular run, we additionally set up the aggregator.
	// The aggregator will grab the events from the queue, assemble them
	// into batches and hand over to output sinks.
	filamentName := cfg.Filament.Name
	if filamentName != "" {
		f.filament, err = filament.New(filamentName, f.psnap, f.hsnap, cfg)
		if err != nil {
			return err
		}
		if f.filament.Filter() != nil {
			f.evs.SetFilter(f.filament.Filter())
		}
		err = f.evs.Open(cfg)
		if err != nil {
			return multierror.Wrap(err, f.evs.Close())
		}
		// load alert senders so emitting alerts is possible from filaments
		err = alertsender.LoadAll(cfg.Alertsenders)
		if err != nil {
			log.Warnf("couldn't load alertsenders: %v", err)
		}
		go func() {
			err = f.filament.Run(f.evs.Events(), f.evs.Errors())
			if err != nil {
				log.Errorf("filament failed: %v", err)
				f.stop()
			}
		}()
	} else {
		// register stack symbolizer
		if cfg.Kstream.StackEnrichment {
			f.symbolizer = symbolize.NewSymbolizer(symbolize.NewDebugHelpResolver(cfg), f.psnap, cfg, false)
			f.evs.RegisterEventListener(f.symbolizer)
		}
		// register rule engine
		if f.rules != nil {
			f.evs.RegisterEventListener(f.rules)
		}
		// register YARA scanner
		if cfg.Yara.Enabled {
			scanner, err := yara.NewScanner(f.psnap, cfg.Yara)
			if err != nil {
				return err
			}
			f.evs.RegisterEventListener(scanner)
		}
		err = f.evs.Open(cfg)
		if err != nil {
			return multierror.Wrap(err, f.evs.Close())
		}
		// set up the aggregator that forwards events to outputs
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
	}
	// start the HTTP server
	return api.StartServer(cfg)
}

// WriteCapture writes the event stream to the capture file.
func (f *App) WriteCapture(args []string) error {
	if f.evs == nil {
		panic("event source is nil")
	}

	if !f.isSingleInstance() {
		return ErrAlreadyRunning
	}

	kfilter, err := filter.NewFromCLI(args, f.config)
	if err != nil {
		return err
	}
	if kfilter != nil {
		f.evs.SetFilter(kfilter)
	}
	err = f.evs.Open(f.config)
	if err != nil {
		return err
	}
	f.writer, err = kcap.NewWriter(f.config.KcapFile, f.psnap, f.hsnap)
	if err != nil {
		return err
	}
	errsChan := f.writer.Write(f.evs.Events(), f.evs.Errors())
	go func() {
		for err := range errsChan {
			log.Warnf("fail to write event to capture: %v", err)
		}
	}()
	return api.StartServer(f.config)
}

// ReadCapture reconstructs the event stream from the capture file.
func (f *App) ReadCapture(ctx context.Context, args []string) error {
	if f.reader == nil {
		panic("reader is nil")
	}
	kfilter, err := filter.NewFromCLIWithAllAccessors(args)
	if err != nil {
		return err
	}
	f.hsnap, f.psnap, err = f.reader.RecoverSnapshotters()
	if err != nil {
		return err
	}
	filamentName := f.config.Filament.Name
	if filamentName != "" {
		f.filament, err = filament.New(filamentName, f.psnap, f.hsnap, f.config)
		if err != nil {
			return err
		}
		if f.filament.Filter() != nil {
			// filament filter overrides CLI filter
			f.reader.SetFilter(f.filament.Filter())
		} else if kfilter != nil {
			f.reader.SetFilter(kfilter)
		}
		// returns the channel where events are read from the kcap
		evts, errs := f.reader.Read(ctx)
		go func() {
			defer f.filament.Close()
			err = f.filament.Run(evts, errs)
			if err != nil {
				log.Errorf("filament failed: %v", err)
				f.stop()
			}
		}()
	} else {
		if kfilter != nil {
			f.reader.SetFilter(kfilter)
		}
		// use the channels where events are read
		// from the capture as aggregator source
		evts, errs := f.reader.Read(ctx)
		f.agg, err = aggregator.NewBuffered(
			evts,
			errs,
			f.config.Aggregator,
			f.config.Output,
			f.config.Transformers,
			f.config.Alertsenders,
		)
		if err != nil {
			return err
		}
	}
	return api.StartServer(f.config)
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
	if f.symbolizer != nil {
		f.symbolizer.Close()
	}
	if f.evs != nil {
		if err := f.evs.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if f.hsnap != nil {
		if err := f.hsnap.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if f.psnap != nil {
		if err := f.psnap.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if f.filament != nil {
		if err := f.filament.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if f.writer != nil {
		if err := f.writer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if f.reader != nil {
		if err := f.reader.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if f.agg != nil {
		if err := f.agg.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := handle.CloseTimeout(); err != nil {
		errs = append(errs, err)
	}
	if err := api.CloseServer(); err != nil {
		errs = append(errs, err)
	}
	if err := alertsender.ShutdownAll(); err != nil {
		errs = append(errs, err)
	}
	return multierror.Wrap(errs...)
}

func (f *App) stop() {
	if f.signals != nil {
		f.signals <- struct{}{}
	}
}

// isSingleInstance checks if there is a single instance
// of the Fibratus process running in the system. This is
// accomplished by creating a global event object. If such
// an object already exists, we can conclude Fibratus process
// is already running.
func (f *App) isSingleInstance() bool {
	name, err := windows.UTF16PtrFromString("Global\\Fibratus")
	if err != nil {
		return false
	}
	event, err := windows.CreateEvent(nil, 0, 0, name)
	return event != 0 && !errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}
