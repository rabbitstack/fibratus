// +build filament,windows

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

package filament

import (
	"github.com/jedib0t/go-pretty/v6/table"
	"io"
)

type tab struct {
	writer table.Writer
}

func newTable() tab {
	writer := table.NewWriter()
	writer.SetStyle(table.StyleLight)
	return tab{writer: writer}
}

func (t tab) setWriter(output io.Writer) {
	t.writer.SetOutputMirror(output)
}

func (t tab) setColumnConfigs(cols []string, maxWidth int) {
	configs := make([]table.ColumnConfig, len(cols))
	for i, col := range cols {
		configs[i] = table.ColumnConfig{Name: col, WidthMax: maxWidth}
	}
	t.writer.SetColumnConfigs(configs)
}

func (t tab) appendHeader(cols []string) {
	r := make(table.Row, len(cols))
	for i, col := range cols {
		r[i] = col
	}
	t.writer.AppendHeader(r)
}

func (t tab) appendRow(row []interface{}) {
	t.writer.AppendRow(row)
}

func (t tab) sortBy(column string) {
	t.writer.SortBy([]table.SortBy{{Name: column, Mode: table.DscNumeric}})
}

func (t tab) maxRows(size int) {
	t.writer.SetPageSize(size)
}

func (t tab) render() {
	t.writer.Render()
}

func (t tab) reset() {
	t.writer.ResetRows()
}

func (t tab) title(title string) {
	t.writer.SetTitle(title)
}
