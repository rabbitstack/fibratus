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
	"fmt"
	"time"

	"github.com/rabbitstack/fibratus/cmd/fibratus/common"
	"github.com/rabbitstack/fibratus/pkg/aggregator"
	"github.com/rabbitstack/fibratus/pkg/api"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/handle"
	"github.com/rabbitstack/fibratus/pkg/kstream"
	"github.com/rabbitstack/fibratus/pkg/ps"
	ver "github.com/rabbitstack/fibratus/pkg/util/version"
	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

var startSvcCmd = &cobra.Command{
	Use:   "start-service",
	RunE:  startService,
	Short: "Start fibratus service",
}

var stopSvcCmd = &cobra.Command{
	Use:   "stop-service",
	RunE:  stopService,
	Short: "Stop fibratus service",
}

var restartSvcCmd = &cobra.Command{
	Use:   "restart-service",
	RunE:  restartService,
	Short: "Restart fibratus service",
}

var (
	// windows service command config
	svcConfig = config.NewWithOpts(config.WithRun())

	// windows event logger
	evtlog debug.Log

	ctrl     kstream.KtraceController
	consumer kstream.Consumer
	aggr     *aggregator.BufferedAggregator
)

func init() {
	// initialize service config
	svcConfig.MustViperize(startSvcCmd)
}

func startService(cmd *cobra.Command, args []string) error {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("couldn't connect to Windows Service Manager: %v", err)
	}
	m := &mgr.Mgr{Handle: h}
	defer func() {
		_ = m.Disconnect()
	}()
	s, err := windows.OpenService(
		m.Handle,
		windows.StringToUTF16Ptr(svcName),
		windows.SERVICE_START|windows.SERVICE_STOP,
	)
	if err != nil {
		return fmt.Errorf("could not open fibratus service: %v", err)
	}
	scm := &mgr.Service{Name: svcName, Handle: s}
	defer func() {
		_ = scm.Close()
	}()
	err = scm.Start()
	if err != nil {
		return fmt.Errorf("could not start fibratus service: %v", err)
	}

	start := time.Now()
	var status svc.Status
	for time.Since(start) > 5*time.Second {
		status, err = scm.Query()
		if err != nil {
			return fmt.Errorf("failed to get fibratus service status: %v", err)
		}

		if status.State == svc.Running {
			return nil
		}
	}
	return nil
}

func stopService(cmd *cobra.Command, args []string) error {
	return stopSvc()
}

func restartService(cmd *cobra.Command, args []string) error {
	if err := stopSvc(); err != nil {
		return err
	}
	return startService(cmd, args)
}

func stopSvc() error {
	h, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return fmt.Errorf("couldn't connect to Windows Service Manager: %v", err)
	}
	m := &mgr.Mgr{Handle: h}
	defer func() {
		_ = m.Disconnect()
	}()

	s, err := windows.OpenService(
		m.Handle,
		windows.StringToUTF16Ptr(svcName),
		windows.SERVICE_START|windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS,
	)
	if err != nil {
		return fmt.Errorf("could not open fibratus service: %v", err)
	}
	scm := &mgr.Service{Name: svcName, Handle: s}
	defer func() {
		_ = scm.Close()
	}()

	status, err := scm.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("couldn't stop fibratus service: %v", err)
	}
	timeout := time.Now().Add(10 * time.Second)
	for status.State != svc.Stopped {
		if timeout.Before(time.Now()) {
			return fmt.Errorf("timeout waiting for service to go to state=%d", svc.Stopped)
		}
		time.Sleep(300 * time.Millisecond)
		status, err = scm.Query()
		if err != nil {
			return fmt.Errorf("could not retrieve service status: %v", err)
		}
	}
	return nil
}

type fsvc struct{}

func (s *fsvc) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown
	changes <- svc.Status{State: svc.StartPending}
	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	if err := s.run(); err != nil {
		_ = evtlog.Error(0xc000000B, err.Error())
		changes <- svc.Status{State: svc.Stopped}
		return false, 1
	}

loop:
	for {
		c := <-r
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
			time.Sleep(100 * time.Millisecond)
			changes <- c.CurrentStatus
		case svc.Stop:
			break loop
		case svc.Shutdown:
			break loop
		}
	}

	changes <- svc.Status{State: svc.StopPending}

	if ctrl != nil {
		_ = ctrl.CloseKtrace()
	}
	if consumer != nil {
		_ = consumer.CloseKstream()
	}
	if aggr != nil {
		_ = aggr.Stop()
	}
	_ = handle.CloseTimeout()
	_ = api.CloseServer()

	changes <- svc.Status{State: svc.Stopped}

	return true, 0
}

func (s *fsvc) run() error {
	// initialize config and logger
	if err := common.Init(svcConfig, true); err != nil {
		return err
	}
	ver.Set(version)
	ctrl = kstream.NewKtraceController(svcConfig.Kstream)
	err := ctrl.StartKtrace()
	if err != nil {
		return err
	}

	// initialize handle/process snapshotters and try to open the kernel event stream
	hsnap := handle.NewSnapshotter(svcConfig, nil)
	psnap := ps.NewSnapshotter(hsnap, svcConfig)
	consumer = kstream.NewConsumer(ctrl, psnap, hsnap, svcConfig)
	// open the kernel event stream, start processing events and forwarding to outputs
	err = consumer.OpenKstream(ctrl.Traces())
	if err != nil {
		return err
	}

	aggr, err = aggregator.NewBuffered(
		consumer.Events(),
		consumer.Errors(),
		svcConfig.Aggregator,
		svcConfig.Output,
		svcConfig.Transformers,
		svcConfig.Alertsenders,
	)
	if err != nil {
		return err
	}
	if err := api.StartServer(svcConfig); err != nil {
		return err
	}

	return nil
}

// RunService runs the service handler.
func RunService() {
	var err error
	evtlog, err = eventlog.Open(svcName)
	if err != nil {
		return
	}
	defer func() {
		_ = evtlog.Close()
	}()

	err = svc.Run(svcName, &fsvc{})
	if err != nil {
		_ = evtlog.Error(0xc0000008, err.Error())
		return
	}
}
