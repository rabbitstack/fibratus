//go:build linux

/*
 * Copyright 2019-2020 by Nedim Sabic Sabic
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

package app

import (
	"github.com/rabbitstack/fibratus/internal/bootstrap"
	"github.com/rabbitstack/fibratus/pkg/config"
	ver "github.com/rabbitstack/fibratus/pkg/util/version"
	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:     "run [filter]",
	Short:   "Bootstrap fibratus",
	Aliases: []string{"start"},
	RunE:    run,
}

var cfg = config.NewWithOpts(config.WithRun())

func init() {
	cfg.MustViperize(runCmd)
}

func run(_ *cobra.Command, args []string) error {
	ver.Set(version)
	app, err := bootstrap.NewApp(cfg, bootstrap.WithSignals())
	if err != nil {
		return err
	}
	if err := app.Run(args); err != nil {
		_ = app.Shutdown()
		return err
	}
	app.Wait()
	return app.Shutdown()
}
