/*
 * Copyright 2021-2022 by Nedim Sabic Sabic
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

package rules

import (
	"fmt"
	"github.com/enescakir/emoji"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rabbitstack/fibratus/internal/bootstrap"
	"os"
	"strings"
)

func listRules() error {
	if err := bootstrap.InitConfigAndLogger(cfg); err != nil {
		return err
	}
	if err := cfg.Filters.LoadFilters(); err != nil {
		return fmt.Errorf("%v %v", emoji.DisappointedFace, err)
	}
	filters := cfg.GetFilters()
	if len(filters) == 0 {
		return fmt.Errorf("%v no rules found in %s", emoji.DisappointedFace, strings.Join(cfg.Filters.Rules.FromPaths, ","))
	}

	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)

	// render summary
	if summarized {
		t.AppendHeader(table.Row{"Tactic", "# Rules"})
		t.SetColumnConfigs([]table.ColumnConfig{
			{Name: "Tactic", WidthMin: 50, WidthMax: 50},
			{Name: "#", WidthMin: 50, WidthMax: 50},
		})
		tactics := make(map[string]int)
		techniques := make(map[string]int)
		for _, f := range filters {
			tactics[f.Labels["tactic.name"]]++
			techniques[f.Labels["technique.name"]]++
		}
		tot := 0
		for tac, n := range tactics {
			t.AppendRow(table.Row{tac, n})
			tot += n
		}

		t.AppendSeparator()
		t.AppendRow(table.Row{"TECHNIQUE", "# RULES"})
		t.AppendSeparator()

		for tec, n := range techniques {
			t.AppendRow(table.Row{tec, n})
		}

		t.AppendFooter(table.Row{"TOTAL", tot})
	} else {
		// show all rules
		t.AppendHeader(table.Row{"#", "Rule", "Technique", "Tactic"})
		t.SetColumnConfigs([]table.ColumnConfig{
			{Name: "#", WidthMax: 5},
			{Name: "Rule"},
			{Name: "Technique"},
			{Name: "Tactic", WidthMax: 50},
		})

		n := 0
		tactics := make(map[string]int)
		techniques := make(map[string]int)

		for _, f := range filters {
			tac := f.Labels["tactic.name"]
			tec := f.Labels["technique.name"]
			if _, ok := tactics[tac]; !ok {
				tactics[tac] = 1
			}
			if _, ok := tactics[tec]; !ok {
				techniques[tec] = 1
			}
			t.AppendRow(table.Row{n + 1, f.Name, tec, tac})
			n++
		}

		var (
			totTat int
			totTec int
		)

		for _, n := range tactics {
			totTat += n
		}
		for _, n := range techniques {
			totTec += n
		}

		t.AppendFooter(table.Row{"TOTAL", n, totTec, totTat})
	}

	t.Render()

	return nil
}
