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

package replay

import (
	"context"
	"github.com/rabbitstack/fibratus/pkg/kevent"

	"github.com/rabbitstack/fibratus/cmd/fibratus/common"
	"github.com/rabbitstack/fibratus/pkg/aggregator"
	"github.com/rabbitstack/fibratus/pkg/api"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filament"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/kcap"
	ver "github.com/rabbitstack/fibratus/pkg/util/version"
	"github.com/spf13/cobra"
)

var Version string

var Command = &cobra.Command{
	Use:   "replay",
	Short: "Replay kernel event flow from the kcap file",
	RunE:  replay,
}

var (
	// replay command config
	cfg = config.NewWithOpts(config.WithReplay())
)

func init() {
	cfg.MustViperize(Command)
}

func replay(cmd *cobra.Command, args []string) error {
	if err := common.InitConfigAndLogger(cfg); err != nil {
		return err
	}
	ver.Set(Version)

	// set up the signals
	stopCh := common.Signals()

	kfilter, err := filter.NewFromCLIWithAllAccessors(args)
	if err != nil {
		return err
	}

	// initialize kcap reader and try to recover the snapshotters
	// from the captured state
	reader, err := kcap.NewReader(cfg.KcapFile, cfg)
	if err != nil {
		return err
	}
	hsnap, psnap, err := reader.RecoverSnapshotters()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	// stop kcap reader consumers
	defer cancel()

	filamentName := cfg.Filament.Name
	// we don't need the aggregator is user decided to replay the
	// kcap on the filament. Otherwise, we set up the full-fledged
	// buffered aggregator
	var agg *aggregator.BufferedAggregator

	if filamentName != "" {
		f, err := filament.New(filamentName, psnap, hsnap, cfg)
		if err != nil {
			return err
		}
		if f.Filter() != nil {
			kfilter = f.Filter()
		}
		reader.SetFilter(kfilter)

		// returns the channel where events are read from the kcap
		kevents, errs := reader.Read(ctx)

		go func() {
			defer f.Close()
			err = f.Run(kevents, errs)
			if err != nil {
				stopCh <- struct{}{}
			}
		}()
	} else {
		if kfilter != nil {
			reader.SetFilter(kfilter)
		}

		// use the channels where events are read from the kcap as aggregator source
		kevents, errs := reader.Read(ctx)

		var err error
		agg, err = aggregator.NewBuffered(
			kevents,
			errs,
			cfg.Aggregator,
			cfg.Output,
			cfg.Transformers,
			cfg.Alertsenders,
			func(kevt *kevent.Kevent) bool { return true },
		)
		if err != nil {
			return err
		}
	}
	// start the HTTP server
	if err := api.StartServer(cfg); err != nil {
		return err
	}

	<-stopCh

	if agg != nil {
		if err := agg.Stop(); err != nil {
			return err
		}
	}
	if err := api.CloseServer(); err != nil {
		return err
	}

	return nil
}
