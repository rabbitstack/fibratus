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
	"context"

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

var replayCmd = &cobra.Command{
	Use:   "replay",
	Short: "Replay kernel event flow from the kcap file",
	RunE:  replay,
}

var (
	// replay command config
	replayConfig = config.NewWithOpts(config.WithReplay())
)

func init() {
	replayConfig.MustViperize(replayCmd)
}

func replay(cmd *cobra.Command, args []string) error {
	// initialize config and logger
	if err := common.Init(replayConfig, false); err != nil {
		return err
	}
	ver.Set(version)
	// set up the signals
	stopCh := common.Signals()

	kfilter, err := filter.NewFromCLIWithAllAccessors(args)
	if err != nil {
		return err
	}

	// initialize kcap reader and try to recover the snapshotters
	// from the captured state
	reader, err := kcap.NewReader(replayConfig.KcapFile, replayConfig)
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

	filamentName := replayConfig.Filament.Name
	// we don't need the aggregator is user decided to replay the
	// kcap on the filament. Otherwise, we setup the full-fledged
	// buffered aggregator
	var agg *aggregator.BufferedAggregator

	if filamentName != "" {
		f, err := filament.New(filamentName, psnap, hsnap, replayConfig)
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
			replayConfig.Aggregator,
			replayConfig.Output,
			replayConfig.Transformers,
			replayConfig.Alertsenders,
		)
		if err != nil {
			return err
		}
	}
	// start the HTTP server
	if err := api.StartServer(replayConfig); err != nil {
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
