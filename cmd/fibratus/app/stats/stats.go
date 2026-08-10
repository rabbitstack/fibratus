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

package stats

import (
	"encoding/json"
	"github.com/rabbitstack/fibratus/internal/bootstrap"
	"os"
	"reflect"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rabbitstack/fibratus/pkg/config"
	errs "github.com/rabbitstack/fibratus/pkg/errors"
	"github.com/rabbitstack/fibratus/pkg/util/rest"
	"github.com/spf13/cobra"
)

var Command = &cobra.Command{
	Use:   "stats",
	Short: "Show runtime stats",
	RunE:  stats,
}

var cfg = config.NewWithOpts(config.WithStats())

func init() {
	cfg.MustViperize(Command)
}

func stats(cmd *cobra.Command, args []string) error {
	if err := bootstrap.InitConfigAndLogger(cfg); err != nil {
		return err
	}
	c := cfg.API
	body, err := rest.Get(rest.WithTransport(c.Transport), rest.WithURI("debug/vars"))
	if err != nil {
		return errs.ErrHTTPServerUnavailable(c.Transport, err)
	}
	var stats Stats
	if err := json.Unmarshal(body, &stats); err != nil {
		return err
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Value"})
	t.SetStyle(table.StyleLight)

	typ := reflect.TypeOf(stats)
	val := reflect.ValueOf(stats)

	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag := f.Tag.Get("json")

		if tag == "" {
			continue
		}
		if !val.Field(i).CanInterface() {
			continue
		}
		t.AppendRow(table.Row{tag, val.Field(i).Interface()})
	}

	t.Render()

	return nil
}
