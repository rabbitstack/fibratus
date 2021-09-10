/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package app

import (
	"os"

	"github.com/rabbitstack/fibratus/cmd/fibratus/common"
	"github.com/rabbitstack/fibratus/pkg/aggregator"
	"github.com/rabbitstack/fibratus/pkg/api"
	"github.com/rabbitstack/fibratus/pkg/config"
	kerrors "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/kstream"
	"github.com/rabbitstack/fibratus/pkg/util/user"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:     "run [filter]",
	Short:   "Bootstrap fibratus or a filament",
	Aliases: []string{"start"},
	RunE:    run,
	Example: `
	# Run without the filter
	fibratus run

	# Run with the filter that drops all but events produced by the dnsmasq process
	fibratus run ps.name = 'dnsmasq'
	`,
}

var (
	// the run command config
	cfg = config.NewWithOpts(config.WithRun())
)

func init() {
	// initialize flags
	cfg.MustViperize(runCmd)
}

func run(cmd *cobra.Command, args []string) error {
	if !user.IsRoot() {
		return kerrors.ErrNotRoot
	}
	// initialize config and logger
	if err := common.SetupConfigAndLogger(cfg); err != nil {
		return err
	}
	// set up the signals
	stopCh := common.Signals()

	// try to load the kprobe by reading the embedded
	// bytecode and parsing all of the ELF objects that
	// build up the kprobe program
	kstreamc, err := kstream.NewConsumer()
	if err != nil {
		return err
	}
	// build the filter from the CLI argument. If we got a valid expression the filter
	// is linked to the kernel stream consumer so it can drop any events that don't match
	// the filter criteria
	kfilter, err := filter.NewFromCLI(args, cfg)
	if err != nil {
		return err
	}
	if kfilter != nil {
		kstreamc.SetFilter(kfilter)
	}
	log.Infof("bootstrapping with pid %d", os.Getpid())

	// attach raw tracepoint and poll perf buffer
	if err := kstreamc.OpenKstream(); err != nil {
		return err
	}

	// setup the aggregator that forwards events to outputs
	agg, err := aggregator.NewBuffered(
		kstreamc.Events(),
		kstreamc.Errors(),
		cfg.Aggregator,
		cfg.Output,
		cfg.Transformers,
		cfg.Alertsenders,
	)
	if err != nil {
		return err
	}
	defer func() {
		if err := agg.Stop(); err != nil {
			log.Error(err)
		}
	}()

	// start the HTTP server
	if err := api.StartServer(cfg); err != nil {
		return err
	}

	<-stopCh

	if err := kstreamc.CloseKstream(); err != nil {
		return err
	}

	return api.CloseServer()
}
