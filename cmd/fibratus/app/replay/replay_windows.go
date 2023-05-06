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
	"github.com/rabbitstack/fibratus/internal/bootstrap"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/spf13/cobra"
)

var Command = &cobra.Command{
	Use:   "replay",
	Short: "Replay event stream from the kcap (capture) file",
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
	app, err := bootstrap.NewApp(cfg, bootstrap.WithSignals(), bootstrap.WithCaptureReplay())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := app.ReadCapture(ctx, args); err != nil {
		return err
	}
	app.Wait()
	return app.Shutdown()
}
