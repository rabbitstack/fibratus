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

package console

import (
	"bufio"
	"expvar"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/outputs"
	"os"
)

var (
	consoleErrors = expvar.NewInt("output.console.errors")
)

type format string

const (
	pretty format = "pretty"
	json   format = "json"
	// template represents the default template used in pretty rendering mode
	template = "{{ .Seq }} {{ .Timestamp }} - {{ .CPU }} {{ .Process }} ({{ .Pid }}) - {{ .Type }} ({{ .Kparams }})"
)

type console struct {
	writer    *bufio.Writer
	formatter *kevent.Formatter
	format    format
}

func init() {
	outputs.Register(outputs.Console, initConsole)
}

func initConsole(config outputs.Config) (outputs.OutputGroup, error) {
	stdout := os.Stdout
	cfg, ok := config.Output.(Config)
	if !ok {
		return outputs.Fail(outputs.ErrInvalidConfig(outputs.Console, config.Output))
	}
	tmpl := cfg.Template
	if tmpl == "" {
		tmpl = template
	}
	formatter, err := kevent.NewFormatter(tmpl)
	if err != nil {
		return outputs.Fail(err)
	}
	if cfg.ParamKVDelimiter != "" {
		kevent.ParamKVDelimiter = cfg.ParamKVDelimiter
	}

	c := &console{
		writer:    bufio.NewWriterSize(stdout, 8*1024),
		formatter: formatter,
		format:    format(cfg.Format),
	}
	return outputs.Success(c), nil
}

func (c *console) Close() error   { return c.writer.Flush() }
func (c *console) Connect() error { return nil }
func (c *console) Publish(batch *kevent.Batch) error {
	for _, kevt := range batch.Events {
		var buf []byte
		switch c.format {
		case json:
			buf = kevt.MarshalJSON()
		case pretty:
			buf = c.formatter.Format(kevt)
		default:
			return nil
		}

		if err := c.write(buf); err != nil {
			consoleErrors.Add(1)
			continue
		}
		if err := c.write(nl); err != nil {
			consoleErrors.Add(1)
			continue
		}
	}

	if err := c.writer.Flush(); err != nil {
		consoleErrors.Add(1)
		return err
	}

	return nil
}

var nl = []byte("\n")

func (c *console) write(buf []byte) error {
	written := 0
	for written < len(buf) {
		n, err := c.writer.Write(buf[written:])
		if err != nil {
			return err
		}
		written += n
	}
	return nil
}
