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
	"github.com/rabbitstack/fibratus/internal/bootstrap"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/util/spinner"
	"github.com/spf13/cobra"
	"time"
)

var Command = &cobra.Command{
	Use:   "capture [filter]",
	Short: "Capture event stream to the kcap (capture) file",
	RunE:  capture,
}

var (
	// capture command config
	cfg = config.NewWithOpts(config.WithCapture())
)

func init() {
	cfg.MustViperize(Command)
}

func capture(cmd *cobra.Command, args []string) error {
	spin := spinner.Show("Snapshotting processes and handles")
	defer spin.Stop()
	// the capture will start after all system handles have been
	// enumerated. This gives us a chance to build the handle state
	// before writing the event stream.
	// Make sure to not wait more than a minute if system handle
	// enumeration got stuck or taking too much time to complete
	wait := make(chan struct{}, 1)
	deadline := time.AfterFunc(time.Minute, func() {
		wait <- struct{}{}
	})
	fn := func(total uint64, named uint64) {
		deadline.Stop()
		spin.Stop()
		wait <- struct{}{}
	}
	app, err := bootstrap.NewApp(cfg, bootstrap.WithSignals(), bootstrap.WithDebugPrivilege(),
		bootstrap.WithHandleSnapshotFn(fn))
	if err != nil {
		return err
	}
	<-wait
	if err := app.WriteCapture(args); err != nil {
		return err
	}
	spin = spinner.Show("Capturing")
	app.Wait()
	return app.Shutdown()
}
