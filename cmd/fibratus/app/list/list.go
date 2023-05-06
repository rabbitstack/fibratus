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

package list

import (
	"bufio"
	"fmt"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rabbitstack/fibratus/internal/bootstrap"
	"github.com/rabbitstack/fibratus/pkg/config"
	"github.com/rabbitstack/fibratus/pkg/filter/fields"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strings"
)

var Command = &cobra.Command{
	Use:   "list",
	Short: "Show info about filaments, filter fields or kernel event types",
}

var listFilamentsCmd = &cobra.Command{
	Use:   "filaments",
	Short: "List available filaments",
	RunE:  listFilaments,
}

var listFieldsCmd = &cobra.Command{
	Use:   "fields",
	Short: "List available filtering fields",
	Run:   listFields,
}

var listEventsCmd = &cobra.Command{
	Use:     "kevents",
	Aliases: []string{"events"},
	Short:   "List supported kernel event types",
	Run:     listEvents,
}

var cfg = config.NewWithOpts(config.WithList())

func init() {
	cfg.MustViperize(Command)

	Command.AddCommand(listFilamentsCmd)
	Command.AddCommand(listFieldsCmd)
	Command.AddCommand(listEventsCmd)
}

// listFilaments renders a table with all available filaments.
func listFilaments(cmd *cobra.Command, args []string) error {
	if err := bootstrap.InitConfigAndLogger(cfg); err != nil {
		return err
	}

	dir := cfg.Filament.Path
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%q directory does not exist", dir)
		}
		return err
	}

	filaments, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Description"})
	t.SetStyle(table.StyleLight)

	for _, f := range filaments {
		if f.IsDir() {
			continue
		}
		py, err := os.Open(filepath.Join(dir, f.Name()))
		if err != nil {
			continue
		}
		if filepath.Ext(f.Name()) != ".py" {
			continue
		}

		sn := bufio.NewScanner(py)
		var docStart bool
		var doc string
		for sn.Scan() {
			ln := sn.Text()
			if docStart {
				doc = ln
				break
			}
			if ln == `"""` {
				docStart = true
			}
		}
		_ = py.Close()
		t.AppendRow(table.Row{strings.TrimSuffix(f.Name(), ".py"), doc})
	}
	t.Render()

	return nil
}

// listEvents renders a table with supported event types showing the category
// to which their pertain and a short description of the event.
func listEvents(cmd *cobra.Command, args []string) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Category", "Description"})
	t.SetStyle(table.StyleLight)

	for _, ktyp := range ktypes.GetKtypesMeta() {
		t.AppendRow(table.Row{ktyp.Name, ktyp.Category, ktyp.Description})
	}

	t.Render()
}

// listFields renders a table with available filtering fields containing the name,
// description, filter example, and a column indicating if the field is deprecated.
func listFields(cmd *cobra.Command, args []string) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Name", "Description", "Example", "Deprecation"})
	t.SetStyle(table.StyleLight)

	for _, field := range fields.Get() {
		if field.IsDeprecated() {
			deprecated := fmt.Sprintf("since %s", field.Deprecation.Since)
			t.AppendRow(table.Row{field.Field, field.Desc, strings.Join(field.Examples, ","), deprecated})
		} else {
			t.AppendRow(table.Row{field.Field, field.Desc, strings.Join(field.Examples, ","), ""})
		}
	}
	t.Render()
}
