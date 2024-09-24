//go:build yara
// +build yara

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

package yara

import (
	"bytes"
	"encoding/json"
	"expvar"
	"fmt"
	"github.com/google/uuid"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/rabbitstack/fibratus/pkg/kevent/kparams"
	"github.com/rabbitstack/fibratus/pkg/kevent/ktypes"
	"golang.org/x/sys/windows"

	"github.com/hillu/go-yara/v4"
	"github.com/rabbitstack/fibratus/pkg/alertsender"
	"github.com/rabbitstack/fibratus/pkg/kevent"
	"github.com/rabbitstack/fibratus/pkg/ps"
	pstypes "github.com/rabbitstack/fibratus/pkg/ps/types"
	"github.com/rabbitstack/fibratus/pkg/util/multierror"
	"github.com/rabbitstack/fibratus/pkg/yara/config"
	ytypes "github.com/rabbitstack/fibratus/pkg/yara/types"
	log "github.com/sirupsen/logrus"
)

const alertTitleTmpl = `{{if .PS }}YARA alert on process {{ .PS.Name }}{{ else }}YARA alert on file {{ .Filename }}{{ end }}`

var (
	// ruleMatches computes all the rule matches
	ruleMatches = expvar.NewInt("yara.rule.matches")
	// rulesInCompiler keeps the counter of the number of rules in the compiler
	rulesInCompiler = expvar.NewInt("yara.rules.in.compiler")
	// totalScans computes the number of process/file scans
	totalScans = expvar.NewInt("yara.total.scans")
)

type scanner struct {
	c      *yara.Compiler
	rules  *yara.Rules
	config config.Config

	psnap ps.Snapshotter
}

// AlertContext contains the process state or file name along with all the rule matches.
type AlertContext struct {
	PS        *pstypes.PS
	Filename  string
	Matches   []yara.MatchRule
	Timestamp string
}

const tsLayout = "02 Jan 2006 15:04:05 MST"

// NewScanner creates a new YARA scanner.
func NewScanner(psnap ps.Snapshotter, config config.Config) (Scanner, error) {
	c, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("unable to create yara compiler: %v", err)
	}
	// add yara rules from file system paths by walking the dirs recursively
	for _, dir := range config.Rule.Paths {
		f, err := os.Stat(dir.Path)
		if err != nil {
			log.Warnf("cannot access %q rule path: %v", dir.Path, err)
			continue
		}
		if !f.IsDir() {
			continue
		}
		err = filepath.Walk(dir.Path, func(path string, fi os.FileInfo, err error) error {
			if filepath.Ext(path) != ".yar" {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				log.Warnf("cannot open the rule %q: %v", path, err)
				return nil
			}
			err = c.AddFile(f, dir.Namespace)
			_ = f.Close()
			if err != nil {
				log.Warnf("couldn't add %s rule: %v", fi.Name(), err)
				return nil
			}
			rulesInCompiler.Add(1)

			return nil
		})
		if err != nil {
			log.Warnf("couldn't walk %s path: %v", dir.Path, err)
		}
	}

	// add yara rules from config strings
	for _, s := range config.Rule.Strings {
		err := c.AddString(s.String, s.Namespace)
		if err != nil {
			log.Warnf("couldn't add %s rule string: %v", s.String, err)
			continue
		}
		rulesInCompiler.Add(1)
	}

	if len(c.Errors) > 0 {
		return nil, parseCompilerErrors(c.Errors)
	}

	rules, err := c.GetRules()
	if err != nil {
		return nil, fmt.Errorf("couldn't compile yara rules: %v", err)
	}

	return &scanner{
		c:      c,
		rules:  rules,
		config: config,
		psnap:  psnap,
	}, nil
}

// newInternalScanner creates a new instance of the go-yara scanner.
func (s scanner) newInternalScanner() (*yara.Scanner, error) {
	sn, err := yara.NewScanner(s.rules)
	if err != nil {
		return nil, fmt.Errorf("fail to create yara scanner: %v", err)
	}
	// set scan flags
	var flags yara.ScanFlags
	if s.config.FastScanMode {
		flags |= yara.ScanFlagsFastMode
	}
	sn.SetFlags(flags)
	sn.SetTimeout(s.config.ScanTimeout)
	return sn, nil
}

func parseCompilerErrors(errors []yara.CompilerMessage) error {
	errs := make([]error, len(errors))
	for i, err := range errors {
		errs[i] = fmt.Errorf("%s, filename: %s line: %d", err.Text, err.Filename, err.Line)
	}
	return multierror.Wrap(errs...)
}

func (s scanner) CanEnqueue() bool { return false }

func (s scanner) ProcessEvent(evt *kevent.Kevent) (bool, error) {
	return s.Scan(evt)
}

func (s scanner) Scan(evt *kevent.Kevent) (bool, error) {
	if !evt.IsCreateProcess() && !evt.IsLoadImage() && !evt.IsVirtualAlloc() {
		return false, nil
	}

	var matches yara.MatchRules
	sn, err := s.newInternalScanner()
	if err != nil {
		return false, err
	}

	alertCtx := AlertContext{
		Timestamp: time.Now().Format(tsLayout),
	}

	switch evt.Type {
	case ktypes.CreateProcess:
		pid := evt.Kparams.MustGetPid()
		_, proc := s.psnap.Find(pid)
		if proc == nil {
			return false, fmt.Errorf("%d process not found in snapshotter", pid)
		}
		if s.config.ShouldSkipProcess(proc.Name) {
			return false, nil
		}
		alertCtx.PS = proc
		err = sn.SetCallback(&matches).ScanProc(int(pid))
	case ktypes.LoadImage:
		filename := evt.GetParamAsString(kparams.ImageFilename)
		alertCtx.Filename = filename
		err = sn.SetCallback(&matches).ScanFile(filename)
	case ktypes.VirtualAlloc:
		pid := evt.Kparams.MustGetPid()
		_, proc := s.psnap.Find(pid)
		if proc == nil {
			return false, fmt.Errorf("%d process not found in snapshotter", pid)
		}
		if s.config.ShouldSkipProcess(proc.Name) {
			return false, nil
		}
		protect, err := evt.Kparams.GetUint32(kparams.MemProtect)
		if err != nil {
			return false, err
		}
		if protect != windows.PAGE_EXECUTE_READWRITE {
			return false, nil
		}
		alertCtx.PS = proc
		err = sn.SetCallback(&matches).ScanProc(int(pid))
	}

	if err != nil {
		return false, err
	}
	totalScans.Add(1)
	if len(matches) == 0 {
		return false, nil
	}
	alertCtx.Matches = matches
	ruleMatches.Add(int64(len(matches)))
	if err := putMatchesMeta(matches, evt); err != nil {
		return true, err
	}
	return true, s.send(alertCtx)
}

func (s scanner) send(ctx AlertContext) error {
	if s.config.AlertTitleTemplate == "" {
		s.config.AlertTitleTemplate = alertTitleTmpl
	}
	if s.config.AlertTextTemplate == "" {
		s.config.AlertTextTemplate = alertTextTmpl
	}
	// build a new yara alert template from the config options
	// or use a default template string. We'll feed the alertsender
	// with the output of the parsed template. Template content is
	// rendered by employing the Go templating engine. For more
	// details see https://golang.org/pkg/text/template/
	title, err := executeTmpl(s.config.AlertTitleTemplate, ctx)
	if err != nil {
		return err
	}
	text, err := executeTmpl(s.config.AlertTextTemplate, ctx)
	if err != nil {
		return err
	}

	// fetch the alert sender that is specified in the config
	sender := alertsender.Find(alertsender.ToType(s.config.AlertVia))
	if sender == nil {
		return fmt.Errorf("%q alert sender is not initialized", s.config.AlertVia)
	}

	alert := alertsender.NewAlert(
		title,
		text,
		tagsFromMatches(ctx.Matches),
		alertsender.Normal,
	)
	alert.ID = uuid.New().String()

	log.Infof("emitting yara alert via %q sender: %s", s.config.AlertVia, alert)

	return sender.Send(alert)
}

func executeTmpl(body string, ctx AlertContext) (string, error) {
	var writer bytes.Buffer

	tmpl, err := template.New("yara").Parse(body)
	if err != nil {
		return "", fmt.Errorf("template syntax error: %v", err)
	}
	err = tmpl.Execute(&writer, ctx)
	if err != nil {
		return "", fmt.Errorf("couldn't execute template: %v", err)
	}

	return writer.String(), nil
}

func tagsFromMatches(matches []yara.MatchRule) []string {
	tags := make([]string, 0)
	for _, match := range matches {
		tags = append(tags, match.Tags...)
	}
	return tags
}

// putMatchesMeta injects rule matches into event metadata as a JSON payload.
func putMatchesMeta(matches yara.MatchRules, kevt *kevent.Kevent) error {
	ruleMatches := make([]ytypes.MatchRule, 0)
	for _, m := range matches {
		match := ytypes.MatchRule{
			Rule:      m.Rule,
			Namespace: m.Namespace,
			Tags:      m.Tags,
			Metas:     make([]ytypes.Meta, 0),
			Strings:   make([]ytypes.MatchString, 0),
		}
		for _, meta := range m.Metas {
			match.Metas = append(match.Metas, ytypes.Meta{Value: meta.Value, Identifier: meta.Identifier})
		}
		for _, s := range m.Strings {
			match.Strings = append(match.Strings, ytypes.MatchString{Name: s.Name, Base: s.Base, Data: s.Data, Offset: s.Offset})
		}
		ruleMatches = append(ruleMatches, match)
	}
	b, err := json.Marshal(ruleMatches)
	if err != nil {
		return err
	}
	kevt.AddMeta(kevent.YaraMatchesKey, string(b))
	return nil
}

func (s scanner) Close() {
	if s.c != nil {
		s.c.Destroy()
	}
}
