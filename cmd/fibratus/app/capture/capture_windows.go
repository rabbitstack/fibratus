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

package capture

import (
	"github.com/rabbitstack/fibratus/cmd/fibratus/common"
	"github.com/rabbitstack/fibratus/pkg/api"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kcap"
	"github.com/rabbitstack/fibratus/pkg/kstream"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/rabbitstack/fibratus/pkg/util/spinner"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"time"
)

var Cmd = &cobra.Command{
	Use:   "capture [filter]",
	Short: "Capture kernel event stream to the kcap file",
	RunE:  capture,
}

var (
	// capture command config
	cfg = config.NewWithOpts(config.WithCapture())
)

func init() {
	cfg.MustViperize(Cmd)
}

func capture(cmd *cobra.Command, args []string) error {
	// initialize config and logger
	if err := common.Init(cfg, true); err != nil {
		return err
	}

	// set up the signals
	stopCh := common.Signals()

	spin := spinner.Show("Snapshotting processes and handles")
	// make sure to not wait more than a minute if system handle enumeration
	// got stuck or taking too much time to complete.
	wait := make(chan struct{}, 1)
	deadline := time.AfterFunc(time.Minute, func() {
		wait <- struct{}{}
	})
	cb := func(total uint64, withName uint64) {
		deadline.Stop()
		spin.Stop()
		wait <- struct{}{}
	}

	// the capture will start after all system handles have been enumerated. This gives us a
	// chance to build the handle state before writing the event flow
	hsnap := handle.NewSnapshotter(cfg, cb)
	psnap := ps.NewSnapshotter(hsnap, cfg)

	// we'll start writing to the kcap file once we receive on the wait channel
	<-wait

	// initiate the kernel trace and start consuming from the event stream
	ktracec := kstream.NewKtraceController(cfg.Kstream)
	err := ktracec.StartKtrace()
	if err != nil {
		return err
	}

	kstreamc := kstream.NewConsumer(psnap, hsnap, cfg)
	kfilter, err := filter.NewFromCLI(args, cfg)
	if err != nil {
		return err
	}
	if kfilter != nil {
		kstreamc.SetFilter(kfilter)
	}

	err = kstreamc.OpenKstream(ktracec.Traces())
	if err != nil {
		return multierror.Wrap(err, ktracec.CloseKtrace())
	}
	defer func() {
		_ = ktracec.CloseKtrace()
		_ = kstreamc.CloseKstream()
	}()

	// bootstrap kcap writer with inbound event channel
	writer, err := kcap.NewWriter(cfg.KcapFile, psnap, hsnap)
	if err != nil {
		return err
	}
	errsc := writer.Write(kstreamc.Events(), kstreamc.Errors())

	go func() {
		for err := range errsc {
			log.Warnf("fail to write event to kcap: %v", err)
		}
	}()

	// start rendering the spinner
	spin = spinner.Show("Capturing")

	// start the HTTP server
	if err := api.StartServer(cfg); err != nil {
		return err
	}

	<-stopCh
	spin.Stop()

	if err := writer.Close(); err != nil {
		return err
	}
	if err := api.CloseServer(); err != nil {
		return err
	}

	return nil
}
