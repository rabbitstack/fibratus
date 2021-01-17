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
	"github.com/rabbitstack/fibratus/pkg/api"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kcap"
	"github.com/rabbitstack/fibratus/pkg/kstream"
	"github.com/rabbitstack/fibratus/pkg/ps"
	"github.com/rabbitstack/fibratus/pkg/syscall/security"
	logger "github.com/rabbitstack/fibratus/pkg/util/log"
	"github.com/rabbitstack/fibratus/pkg/util/spinner"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var captureCmd = &cobra.Command{
	Use:   "capture [filter]",
	Short: "Capture kernel event stream to the kcap file",
	RunE:  capture,
}

var captureConfig = config.NewWithOpts(config.WithCapture())

func init() {
	captureConfig.MustViperize(captureCmd)
}

func capture(cmd *cobra.Command, args []string) error {
	if err := captureConfig.TryLoadFile(captureConfig.File()); err != nil {
		return err
	}
	if err := captureConfig.Init(); err != nil {
		return err
	}
	if err := captureConfig.Validate(); err != nil {
		return err
	}
	if captureConfig.DebugPrivilege {
		security.SetDebugPrivilege()
	}
	if err := logger.InitFromConfig(captureConfig.Log); err != nil {
		return err
	}

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
	hsnap := handle.NewSnapshotter(captureConfig, cb)
	psnap := ps.NewSnapshotter(hsnap, captureConfig)

	// we'll start writing to the kcap file once we receive on the wait channel
	<-wait

	// initiate the kernel trace and start consuming from the event stream
	ktracec := kstream.NewKtraceController(captureConfig.Kstream)
	err := ktracec.StartKtrace()
	if err != nil {
		return err
	}
	defer func() {
		_ = ktracec.CloseKtrace()
	}()

	kstreamc := kstream.NewConsumer(ktracec, psnap, hsnap, captureConfig)
	kfilter, err := filter.NewFromCLI(args, captureConfig)
	if err != nil {
		return err
	}
	if kfilter != nil {
		kstreamc.SetFilter(kfilter)
	}
	err = kstreamc.OpenKstream()
	if err != nil {
		return err
	}
	defer func() {
		_ = kstreamc.CloseKstream()
	}()

	// bootstrap kcap writer with inbound event channel
	writer, err := kcap.NewWriter(captureConfig.KcapFile, psnap, hsnap)
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
	if err := api.StartServer(captureConfig); err != nil {
		return err
	}

	signal.Notify(sig, syscall.SIGTERM, os.Interrupt)
	<-sig
	spin.Stop()

	if err := writer.Close(); err != nil {
		return err
	}
	if err := api.CloseServer(); err != nil {
		return err
	}

	return nil
}
